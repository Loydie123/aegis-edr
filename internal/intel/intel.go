package intel

import (
	"context"
	"errors"
	"sync"
	"time"

	"aegis-edr/internal/storage"
)

type IOCType string

const (
	IOCHash        IOCType = "hash"
	IOCDomain      IOCType = "domain"
	IOCURL         IOCType = "url"
	IOCCertificate IOCType = "certificate"
	IOCJA3         IOCType = "ja3"
	IOCJA4         IOCType = "ja4"
	IOCMitre       IOCType = "mitre"
)

type Indicator struct {
	Pattern     string    `json:"pattern"`
	Type        IOCType   `json:"type"`
	Label       string    `json:"label"`
	Version     int       `json:"version"`
	Description string    `json:"description"`
	LastUpdated time.Time `json:"last_updated"`
}

type ReputationEngine struct {
	mu    sync.RWMutex
	cache map[IOCType]map[string]*Indicator
}

func NewReputationEngine() *ReputationEngine {
	return &ReputationEngine{
		cache: map[IOCType]map[string]*Indicator{
			IOCHash:        make(map[string]*Indicator),
			IOCDomain:      make(map[string]*Indicator),
			IOCURL:         make(map[string]*Indicator),
			IOCCertificate: make(map[string]*Indicator),
			IOCJA3:         make(map[string]*Indicator),
			IOCJA4:         make(map[string]*Indicator),
			IOCMitre:       make(map[string]*Indicator),
		},
	}
}

func (re *ReputationEngine) Load(indicators []Indicator) {
	re.mu.Lock()
	defer re.mu.Unlock()

	for _, ind := range indicators {
		if sub, exists := re.cache[ind.Type]; exists {
			sub[ind.Pattern] = &ind
		}
	}
}

func (re *ReputationEngine) Lookup(pattern string, iocType IOCType) (*Indicator, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if sub, exists := re.cache[iocType]; exists {
		ind, found := sub[pattern]
		return ind, found
	}
	return nil, false
}

type FeedManager struct {
	mu          sync.RWMutex
	store       *storage.Storage
	client      *TAXIIClient
	sources     []string
	offlineMode bool
	version     int
}

func NewFeedManager(store *storage.Storage, client *TAXIIClient) *FeedManager {
	return &FeedManager{
		store:   store,
		client:  client,
		sources: make([]string, 0),
		version: 1,
	}
}

func (fm *FeedManager) SetOfflineMode(offline bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.offlineMode = offline
}

func (fm *FeedManager) AddSource(url string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.sources = append(fm.sources, url)
}

func (fm *FeedManager) Sync(ctx context.Context, engine *ReputationEngine) error {
	fm.mu.Lock()
	offline := fm.offlineMode
	sources := make([]string, len(fm.sources))
	copy(sources, fm.sources)
	fm.version++
	currentVer := fm.version
	fm.mu.Unlock()

	if offline {
		return fm.loadOfflineIndicators(ctx, engine)
	}

	hasSuccess := false
	for _, src := range sources {
		err := fm.client.PollFeed(ctx, src, "", "")
		if err == nil {
			hasSuccess = true
		}
	}

	if !hasSuccess && len(sources) > 0 {
		return fm.loadOfflineIndicators(ctx, engine)
	}

	return fm.cacheIndicatorsFromStore(ctx, engine, currentVer)
}

func (fm *FeedManager) loadOfflineIndicators(ctx context.Context, engine *ReputationEngine) error {
	return fm.cacheIndicatorsFromStore(ctx, engine, fm.version)
}

func (fm *FeedManager) cacheIndicatorsFromStore(ctx context.Context, engine *ReputationEngine, ver int) error {
	rows, err := fm.store.RawDBForTest().QueryContext(ctx, "SELECT pattern, pattern_type, threat_label FROM indicators")
	if err != nil {
		return err
	}
	defer rows.Close()

	var list []Indicator
	for rows.Next() {
		var pattern, pType, label string
		if err := rows.Scan(&pattern, &pType, &label); err != nil {
			return err
		}

		t := IOCHash
		switch pType {
		case "domain":
			t = IOCDomain
		case "url":
			t = IOCURL
		case "certificate":
			t = IOCCertificate
		case "ja3":
			t = IOCJA3
		case "ja4":
			t = IOCJA4
		case "mitre":
			t = IOCMitre
		}

		list = append(list, Indicator{
			Pattern:     pattern,
			Type:        t,
			Label:       label,
			Version:     ver,
			Description: "Offline threat intelligence payload",
			LastUpdated: time.Now(),
		})
	}

	engine.Load(list)
	return nil
}

func (fm *FeedManager) IngestMockBundle(data []byte) error {
	if fm.client == nil {
		return errors.New("TAXII client not configured")
	}
	return fm.client.IngestSTIXBundle(data)
}
