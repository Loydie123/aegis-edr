package eventrouter

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	"aegis-edr/internal/logger"
	"aegis-edr/internal/storage"
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
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var batch []*Event
		flush := func() {
			if len(batch) == 0 {
				return
			}
			r.flushBatch(batch)
			batch = nil
		}

		for {
			select {
			case e := <-r.eventChan:
				batch = append(batch, e)
				if len(batch) >= 100 {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-r.closeChan:
				for {
					select {
					case e := <-r.eventChan:
						batch = append(batch, e)
						if len(batch) >= 100 {
							flush()
						}
					default:
						flush()
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
		logger.Log.Error("Queue overflow: dropping event", "type", string(e.Type))
		PutEvent(e)
		return false
	}
}

func (r *Router) flushBatch(batch []*Event) {
	start := time.Now()
	tx, err := r.store.Begin()
	if err != nil {
		logger.Log.Error("failed to begin telemetry database transaction", "error", err)
		for _, e := range batch {
			PutEvent(e)
		}
		return
	}

	ctx := context.Background()
	for _, e := range batch {
		r.processBatchEvent(ctx, tx, e)
		PutEvent(e)
	}

	if err := tx.Commit(); err != nil {
		logger.Log.Error("failed to commit telemetry database transaction", "error", err)
	}

	elapsed := time.Since(start)
	if elapsed > 10*time.Millisecond {
		logger.Log.Warn("Latency threshold breached: transaction flush execution exceeded 10ms",
			"batch_size", len(batch),
			"elapsed", elapsed,
		)
	}
}

func (r *Router) processBatchEvent(ctx context.Context, tx *sql.Tx, e *Event) {
	if e.Type == TypeFile && e.FileAction != "read" && e.FileAction != "open" {
		filePathLower := strings.ToLower(e.FilePath)
		if strings.Contains(filePathLower, "telemetry.db") ||
			strings.Contains(filePathLower, "aegis.yaml") ||
			strings.Contains(filePathLower, "aegisd") ||
			strings.Contains(filePathLower, "aegis.sock") {

			logger.Log.Error("CRITICAL: Self-defense alarm! Unauthorized tamper attempt on agent path!",
				"filepath", e.FilePath,
				"action", e.FileAction,
				"process_id", e.ProcessID,
			)
			_, dbErr := tx.ExecContext(ctx,
				"INSERT INTO alert_logs (rule_name, category, risk_score, description, process_id) VALUES (?, ?, ?, ?, ?)",
				"AGENT_SELF_DEFENSE", "anti-tampering", 1.0,
				"Unauthorized write/modify attempt detected on protected agent path: "+e.FilePath,
				e.ProcessID,
			)
			if dbErr != nil {
				logger.Log.Error("failed to write self-defense alert to database transaction", "error", dbErr)
			}
		}
	}

	var err error
	switch e.Type {
	case TypeProcess:
		_, err = tx.ExecContext(ctx,
			"INSERT INTO processes (parent_id, binary_path, sha256, command_line, username) VALUES (?, ?, ?, ?, ?)",
			e.ParentID, e.BinaryPath, e.SHA256, e.CommandLine, e.Username,
		)
	case TypeFile:
		_, err = tx.ExecContext(ctx,
			"INSERT INTO file_modifications (process_id, file_path, action) VALUES (?, ?, ?)",
			e.ProcessID, e.FilePath, e.FileAction,
		)
	case TypeNetwork:
		_, err = tx.ExecContext(ctx,
			"INSERT INTO network_connections (process_id, protocol, local_ip, local_port, remote_ip, remote_port) VALUES (?, ?, ?, ?, ?, ?)",
			e.ProcessID, e.Protocol, e.LocalIP, e.LocalPort, e.RemoteIP, e.RemotePort,
		)
	}

	if err != nil {
		logger.Log.Error("failed to write telemetry to database transaction", "error", err)
	}
}

func (r *Router) processEvent(e *Event) {
	r.flushBatch([]*Event{e})
}
