package eventrouter

import (
	"strings"
	"sync"
	"time"

	"aegis-edr/internal/logger"
	"aegis-edr/internal/storage"
	"go.uber.org/zap"
)

type EventType string

const (
	TypeProcess EventType = "process"
	TypeFile    EventType = "file"
	TypeNetwork EventType = "network"
)

type Event struct {
	ID          int64
	Type        EventType
	Timestamp   time.Time
	ProcessID   int32
	ParentID    int32
	BinaryPath  string
	SHA256      string
	CommandLine string
	Username    string
	FilePath    string
	FileAction  string
	Protocol    string
	LocalIP     string
	LocalPort   int32
	RemoteIP    string
	RemotePort  int32
}

var eventPool = sync.Pool{
	New: func() interface{} {
		return &Event{}
	},
}

func GetEvent() *Event {
	return eventPool.Get().(*Event)
}

func PutEvent(e *Event) {
	e.ID = 0
	e.Type = ""
	e.Timestamp = time.Time{}
	e.ProcessID = 0
	e.ParentID = 0
	e.BinaryPath = ""
	e.SHA256 = ""
	e.CommandLine = ""
	e.Username = ""
	e.FilePath = ""
	e.FileAction = ""
	e.Protocol = ""
	e.LocalIP = ""
	e.LocalPort = 0
	e.RemoteIP = ""
	e.RemotePort = 0
	eventPool.Put(e)
}

type Router struct {
	eventChan chan *Event
	store     *storage.Storage
	capacity  int
	closeChan chan struct{}
	wg        sync.WaitGroup
}

func NewRouter(capacity int, store *storage.Storage) *Router {
	return &Router{
		eventChan: make(chan *Event, capacity),
		store:     store,
		capacity:  capacity,
		closeChan: make(chan struct{}),
	}
}

func (r *Router) Start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			select {
			case e := <-r.eventChan:
				r.processEvent(e)
			case <-r.closeChan:
				for {
					select {
					case e := <-r.eventChan:
						r.processEvent(e)
					default:
						return
					}
				}
			}
		}
	}()
}

func (r *Router) Stop() {
	close(r.closeChan)
	r.wg.Wait()
}

func (r *Router) Submit(e *Event) bool {
	qLen := len(r.eventChan)
	watermark := int(float64(r.capacity) * 0.8)

	if qLen >= watermark {
		if e.Type == TypeFile && e.FileAction == "read" {
			logger.Log.Warn("Triage mode active: dropping file read event due to queue pressure")
			PutEvent(e)
			return false
		}
	}

	select {
	case r.eventChan <- e:
		return true
	default:
		logger.Log.Error("Queue overflow: dropping event", zap.String("type", string(e.Type)))
		PutEvent(e)
		return false
	}
}

func (r *Router) processEvent(e *Event) {
	start := time.Now()
	defer PutEvent(e)

	if e.Type == TypeFile && e.FileAction != "read" && e.FileAction != "open" {
		filePathLower := strings.ToLower(e.FilePath)
		if strings.Contains(filePathLower, "telemetry.db") ||
			strings.Contains(filePathLower, "aegis.yaml") ||
			strings.Contains(filePathLower, "aegisd") ||
			strings.Contains(filePathLower, "aegis.sock") {

			logger.Log.Error("CRITICAL: Self-defense alarm! Unauthorized tamper attempt on agent path!",
				zap.String("filepath", e.FilePath),
				zap.String("action", e.FileAction),
				zap.Int32("process_id", e.ProcessID),
			)
			_, dbErr := r.store.DB().Exec(
				"INSERT INTO alert_logs (rule_name, category, risk_score, description, process_id, triggered_at) VALUES (?, ?, ?, ?, ?, ?)",
				"AGENT_SELF_DEFENSE", "anti-tampering", 1.0,
				"Unauthorized write/modify attempt detected on protected agent path: "+e.FilePath,
				e.ProcessID, e.Timestamp,
			)
			if dbErr != nil {
				logger.Log.Error("failed to write self-defense alert to database", zap.Error(dbErr))
			}
		}
	}

	var err error
	switch e.Type {
	case TypeProcess:
		_, err = r.store.DB().Exec(
			"INSERT INTO processes (parent_id, binary_path, sha256, command_line, username, launched_at) VALUES (?, ?, ?, ?, ?, ?)",
			e.ParentID, e.BinaryPath, e.SHA256, e.CommandLine, e.Username, e.Timestamp,
		)
	case TypeFile:
		_, err = r.store.DB().Exec(
			"INSERT INTO file_modifications (process_id, file_path, action, occurred_at) VALUES (?, ?, ?, ?)",
			e.ProcessID, e.FilePath, e.FileAction, e.Timestamp,
		)
	case TypeNetwork:
		_, err = r.store.DB().Exec(
			"INSERT INTO network_connections (process_id, protocol, local_ip, local_port, remote_ip, remote_port, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			e.ProcessID, e.Protocol, e.LocalIP, e.LocalPort, e.RemoteIP, e.RemotePort, e.Timestamp,
		)
	}

	if err != nil {
		logger.Log.Error("failed to write telemetry to database", zap.Error(err))
	}

	elapsed := time.Since(start)
	if elapsed > time.Millisecond {
		logger.Log.Warn("Latency threshold breached: telemetry processing exceeded 1ms",
			zap.String("type", string(e.Type)),
			zap.Duration("elapsed", elapsed),
		)
	}
}
