package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegis-edr/internal/logger"
	"aegis-edr/internal/storage"
)

type RawEvent struct {
	Type        string
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

type Event struct {
	ID          int64
	Type        string
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

type Deduplicator struct {
	mu    sync.Mutex
	cache map[string]time.Time
	ttl   time.Duration
}

func NewDeduplicator(ttl time.Duration) *Deduplicator {
	return &Deduplicator{
		cache: make(map[string]time.Time),
		ttl:   ttl,
	}
}

func (d *Deduplicator) IsDuplicate(e *Event) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	var key string
	switch e.Type {
	case "process":
		key = fmt.Sprintf("proc:%d:%s", e.ProcessID, e.BinaryPath)
	case "file":
		key = fmt.Sprintf("file:%d:%s:%s", e.ProcessID, e.FilePath, e.FileAction)
	case "network":
		key = fmt.Sprintf("net:%d:%s:%s:%d", e.ProcessID, e.RemoteIP, e.Protocol, e.RemotePort)
	default:
		key = fmt.Sprintf("other:%s:%d", e.Type, e.Timestamp.Unix())
	}

	now := time.Now()
	if lastSeen, exists := d.cache[key]; exists && now.Sub(lastSeen) < d.ttl {
		return true
	}
	d.cache[key] = now

	if len(d.cache) > 10000 {
		for k, t := range d.cache {
			if now.Sub(t) > d.ttl {
				delete(d.cache, k)
			}
		}
	}
	return false
}

type Filter struct {
	ExcludePaths []string
}

func NewFilter(excludePaths []string) *Filter {
	return &Filter{ExcludePaths: excludePaths}
}

func (f *Filter) ShouldFilter(e *Event) bool {
	if e.Type == "file" {
		for _, prefix := range f.ExcludePaths {
			if strings.HasPrefix(e.FilePath, prefix) {
				return true
			}
		}
	}
	return false
}

type Metrics struct {
	IngestedCount   uint64
	NormalizedCount uint64
	Deduplicated    uint64
	FilteredCount   uint64
	BufferedCount   uint64
	PersistedCount  uint64
}

type Pipeline struct {
	queue            chan *Event
	store            *storage.Storage
	dedup            *Deduplicator
	filter           *Filter
	metrics          *Metrics
	closeChan        chan struct{}
	wg               sync.WaitGroup
	correlationHook  func(*Event)
	analyticsHook    func(*Event)
}

func NewPipeline(capacity int, store *storage.Storage, dedupTTL time.Duration, excludes []string) *Pipeline {
	return &Pipeline{
		queue:     make(chan *Event, capacity),
		store:     store,
		dedup:     NewDeduplicator(dedupTTL),
		filter:    NewFilter(excludes),
		metrics:   &Metrics{},
		closeChan: make(chan struct{}),
	}
}

func (p *Pipeline) SetCorrelationHook(hook func(*Event)) {
	p.correlationHook = hook
}

func (p *Pipeline) SetAnalyticsHook(hook func(*Event)) {
	p.analyticsHook = hook
}

func (p *Pipeline) Ingest(raw *RawEvent) {
	atomic.AddUint64(&p.metrics.IngestedCount, 1)

	normalized := &Event{
		Type:        strings.ToLower(raw.Type),
		Timestamp:   raw.Timestamp,
		ProcessID:   raw.ProcessID,
		ParentID:    raw.ParentID,
		BinaryPath:  raw.BinaryPath,
		SHA256:      raw.SHA256,
		CommandLine: raw.CommandLine,
		Username:    raw.Username,
		FilePath:    raw.FilePath,
		FileAction:  raw.FileAction,
		Protocol:    raw.Protocol,
		LocalIP:     raw.LocalIP,
		LocalPort:   raw.LocalPort,
		RemoteIP:    raw.RemoteIP,
		RemotePort:  raw.RemotePort,
	}

	if normalized.Timestamp.IsZero() {
		normalized.Timestamp = time.Now()
	}

	if normalized.SHA256 == "" && normalized.BinaryPath != "" {
		h := sha256.Sum256([]byte(normalized.BinaryPath))
		normalized.SHA256 = hex.EncodeToString(h[:])
	}

	atomic.AddUint64(&p.metrics.NormalizedCount, 1)

	if p.dedup.IsDuplicate(normalized) {
		atomic.AddUint64(&p.metrics.Deduplicated, 1)
		return
	}

	if p.filter.ShouldFilter(normalized) {
		atomic.AddUint64(&p.metrics.FilteredCount, 1)
		return
	}

	select {
	case p.queue <- normalized:
		atomic.AddUint64(&p.metrics.BufferedCount, 1)
	default:
		logger.Log.Warn("Telemetry queue capacity overflow. Dropping event.")
	}
}

func (p *Pipeline) Start(ctx context.Context) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var batch []*Event
		flush := func() {
			if len(batch) == 0 {
				return
			}
			p.flushBatch(batch)
			batch = nil
		}

		for {
			select {
			case e := <-p.queue:
				batch = append(batch, e)
				if len(batch) >= 100 {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-p.closeChan:
				for {
					select {
					case e := <-p.queue:
						batch = append(batch, e)
						if len(batch) >= 100 {
							flush()
						}
					default:
						flush()
						return
					}
				}
			case <-ctx.Done():
				flush()
				return
			}
		}
	}()
}

func (p *Pipeline) Stop() {
	close(p.closeChan)
	p.wg.Wait()
}

func (p *Pipeline) flushBatch(batch []*Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, e := range batch {
		if p.store != nil {
			var err error
			switch e.Type {
			case "process":
				_, err = p.store.InsertProcess(ctx, int(e.ParentID), e.BinaryPath, e.SHA256, e.CommandLine, e.Username)
			case "file":
				err = p.store.InsertFileModification(ctx, int(e.ProcessID), e.FilePath, e.FileAction)
			case "network":
				err = p.store.InsertNetworkConnection(ctx, int(e.ProcessID), e.Protocol, e.LocalIP, int(e.LocalPort), e.RemoteIP, int(e.RemotePort))
			}
			if err != nil {
				logger.Log.Error("failed to persist normalized event", "error", err)
			} else {
				atomic.AddUint64(&p.metrics.PersistedCount, 1)
			}
		}

		if p.correlationHook != nil {
			p.correlationHook(e)
		}

		if p.analyticsHook != nil {
			p.analyticsHook(e)
		}
	}
}

func (p *Pipeline) Replay(ctx context.Context, start, end time.Time) error {
	if p.store == nil {
		return fmt.Errorf("storage engine not initialized for replay")
	}

	procList, err := p.store.QueryProcesses(ctx, start, end)
	if err == nil {
		for _, pr := range procList {
			p.Ingest(&RawEvent{
				Type:        "process",
				Timestamp:   pr.LaunchedAt,
				ProcessID:   0,
				BinaryPath:  pr.BinaryPath,
				CommandLine: pr.CommandLine,
				Username:    pr.Username,
			})
		}
	}

	fileList, err := p.store.QueryFileModifications(ctx, start, end)
	if err == nil {
		for _, fl := range fileList {
			p.Ingest(&RawEvent{
				Type:       "file",
				Timestamp:  fl.OccurredAt,
				FilePath:   fl.FilePath,
				FileAction: fl.Action,
			})
		}
	}

	netList, err := p.store.QueryNetworkConnections(ctx, start, end)
	if err == nil {
		for _, nt := range netList {
			p.Ingest(&RawEvent{
				Type:       "network",
				Timestamp:  nt.OccurredAt,
				Protocol:   nt.Protocol,
				LocalIP:    nt.LocalIP,
				LocalPort:  int32(nt.LocalPort),
				RemoteIP:   nt.RemoteIP,
				RemotePort: int32(nt.RemotePort),
			})
		}
	}

	return nil
}

func (p *Pipeline) GetMetrics() Metrics {
	return Metrics{
		IngestedCount:   atomic.LoadUint64(&p.metrics.IngestedCount),
		NormalizedCount: atomic.LoadUint64(&p.metrics.NormalizedCount),
		Deduplicated:    atomic.LoadUint64(&p.metrics.Deduplicated),
		FilteredCount:   atomic.LoadUint64(&p.metrics.FilteredCount),
		BufferedCount:   atomic.LoadUint64(&p.metrics.BufferedCount),
		PersistedCount:  atomic.LoadUint64(&p.metrics.PersistedCount),
	}
}
