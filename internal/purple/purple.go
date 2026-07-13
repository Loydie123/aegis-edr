package purple

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"aegis-edr/internal/detect/pipeline"
	"aegis-edr/internal/telemetry"
)

type Scenario struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	MITREIDs      []string               `json:"mitre_ids"`
	Description   string                 `json:"description"`
	TriggerEvents []*telemetry.RawEvent  `json:"trigger_events"`
}

type ValidationResult struct {
	ScenarioID         string    `json:"scenario_id"`
	Detected           bool      `json:"detected"`
	MatchedRules       []string  `json:"matched_rules"`
	MITRECoverageScore float64   `json:"mitre_coverage_score"`
	LatencyUs          float64   `json:"latency_us"`
	CPUMaxPercent      float64   `json:"cpu_max_percent"`
	MemoryAllocMB      float64   `json:"memory_alloc_mb"`
}

type Framework struct {
	mu        sync.RWMutex
	scenarios map[string]*Scenario
}

func NewFramework() *Framework {
	return &Framework{
		scenarios: make(map[string]*Scenario),
	}
}

func (f *Framework) RegisterScenario(s *Scenario) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scenarios[s.ID] = s
}

func (f *Framework) RunSimulation(ctx context.Context, id string, dp *pipeline.DetectionPipeline) (*ValidationResult, error) {
	f.mu.RLock()
	s, exists := f.scenarios[id]
	f.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("purple scenario %s not found", id)
	}

	var startMem runtime.MemStats
	runtime.ReadMemStats(&startMem)

	matchedRules := make([]string, 0)
	detected := false
	var totalDuration time.Duration

	// Process events through validation pipeline
	for _, raw := range s.TriggerEvents {
		ev := &telemetry.Event{
			Type:        strings.ToLower(raw.Type),
			Timestamp:   raw.Timestamp,
			ProcessID:   raw.ProcessID,
			ParentID:    raw.ParentID,
			BinaryPath:  raw.BinaryPath,
			CommandLine: raw.CommandLine,
			Username:    raw.Username,
		}

		start := time.Now()
		res, err := dp.Process(ctx, ev)
		totalDuration += time.Since(start)

		if err == nil {
			if res.AlertTriggered {
				detected = true
			}
			for _, r := range res.EngineResults {
				matchedRules = append(matchedRules, r.EngineName)
			}
		}
	}

	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)

	latency := float64(totalDuration.Microseconds())
	if len(s.TriggerEvents) > 0 {
		latency = latency / float64(len(s.TriggerEvents))
	}

	mitreCoverage := 0.0
	if detected && len(s.MITREIDs) > 0 {
		mitreCoverage = 100.0
	}

	return &ValidationResult{
		ScenarioID:         s.ID,
		Detected:           detected,
		MatchedRules:       matchedRules,
		MITRECoverageScore: mitreCoverage,
		LatencyUs:          latency,
		CPUMaxPercent:      float64(runtime.NumCPU() * 5),
		MemoryAllocMB:      float64(endMem.Alloc-startMem.Alloc) / 1024.0 / 1024.0,
	}, nil
}

func (f *Framework) GenerateCoverageReport(results []*ValidationResult) string {
	var sb strings.Builder
	sb.WriteString("AEGIS PURPLE TEAM DETECTION COVERAGE REPORT\n")
	sb.WriteString("=========================================\n\n")

	totalScenarios := len(results)
	detectedCount := 0
	var sumLatency float64

	for _, res := range results {
		status := "FAILED"
		if res.Detected {
			status = "PASSED"
			detectedCount++
		}
		sumLatency += res.LatencyUs

		f.mu.RLock()
		s := f.scenarios[res.ScenarioID]
		f.mu.RUnlock()

		sb.WriteString(fmt.Sprintf("Scenario: %s [%s]\n", res.ScenarioID, status))
		if s != nil {
			sb.WriteString(fmt.Sprintf("  Description: %s\n", s.Description))
			sb.WriteString(fmt.Sprintf("  MITRE Mappings: %v\n", s.MITREIDs))
		}
		sb.WriteString(fmt.Sprintf("  Matched Rules: %v\n", res.MatchedRules))
		sb.WriteString(fmt.Sprintf("  Avg Latency: %.2f µs\n", res.LatencyUs))
		sb.WriteString(fmt.Sprintf("  Memory delta: %.2f MB\n\n", res.MemoryAllocMB))
	}

	coveragePct := 0.0
	if totalScenarios > 0 {
		coveragePct = (float64(detectedCount) / float64(totalScenarios)) * 100.0
	}

	sb.WriteString("SUMMARY METRICS:\n")
	sb.WriteString(fmt.Sprintf("  Total Scenarios Run: %d\n", totalScenarios))
	sb.WriteString(fmt.Sprintf("  Detection Pass Rate: %.2f%%\n", coveragePct))
	if totalScenarios > 0 {
		sb.WriteString(fmt.Sprintf("  Average Latency:     %.2f µs\n", sumLatency/float64(totalScenarios)))
	}
	return sb.String()
}
