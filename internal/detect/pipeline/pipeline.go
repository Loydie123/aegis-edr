package pipeline

import (
	"context"
	"strings"

	"aegis-edr/internal/scoring"
	"aegis-edr/internal/telemetry"
)

type DetectionContext struct {
	EngineResults  []scoring.EngineResult
	Matches        []string
	AlertTriggered bool
	AlertDetail    scoring.Alert
}

type DetectionStage interface {
	Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error
	Name() string
}

type DetectionPipeline struct {
	stages []DetectionStage
}

func NewDetectionPipeline(stages ...DetectionStage) *DetectionPipeline {
	return &DetectionPipeline{stages: stages}
}

func (dp *DetectionPipeline) Process(ctx context.Context, e *telemetry.Event) (*DetectionContext, error) {
	ctxData := &DetectionContext{
		EngineResults: make([]scoring.EngineResult, 0),
		Matches:       make([]string, 0),
	}

	for _, stage := range dp.stages {
		_ = stage.Process(ctx, e, ctxData)
	}

	return ctxData, nil
}

type NormalizerStage struct{}

func (s *NormalizerStage) Name() string { return "Normalizer" }
func (s *NormalizerStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	e.BinaryPath = strings.TrimSpace(e.BinaryPath)
	e.SHA256 = strings.ToLower(strings.TrimSpace(e.SHA256))
	return nil
}

type BehaviorAnalysisStage struct{}

func (s *BehaviorAnalysisStage) Name() string { return "BehaviorAnalysis" }
func (s *BehaviorAnalysisStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if e.Type == "process" && e.ParentID == 1 {
		ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
			EngineName: "BehaviorAnalysis",
			Severity:   3.0,
			Weight:     0.5,
			MITREIDs:   []string{"T1059"},
		})
		ctxData.Matches = append(ctxData.Matches, "Process spawned directly by system init")
	}
	return nil
}

type HeuristicStage struct {
	entropyThreshold float64
}

func NewHeuristicStage(threshold float64) *HeuristicStage {
	return &HeuristicStage{entropyThreshold: threshold}
}

func (s *HeuristicStage) Name() string { return "Heuristic" }
func (s *HeuristicStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if strings.Contains(e.CommandLine, "-nop") || strings.Contains(e.CommandLine, "-enc") {
		ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
			EngineName: "Heuristic",
			Severity:   6.5,
			Weight:     0.7,
			MITREIDs:   []string{"T1059.001"},
		})
		ctxData.Matches = append(ctxData.Matches, "Anomalous command line argument detected")
	}
	return nil
}

type IOCMatchingStage struct {
	iocList map[string]string
}

func NewIOCMatchingStage(iocList map[string]string) *IOCMatchingStage {
	return &IOCMatchingStage{iocList: iocList}
}

func (s *IOCMatchingStage) Name() string { return "IOCMatching" }
func (s *IOCMatchingStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if label, exists := s.iocList[e.SHA256]; exists {
		ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
			EngineName: "IOCMatching",
			Severity:   9.5,
			Weight:     0.9,
			MITREIDs:   []string{"T1204.002"},
		})
		ctxData.Matches = append(ctxData.Matches, "Matched known malicious payload hash: "+label)
	}
	return nil
}

type YaraStage struct {
	rules map[string]bool
}

func NewYaraStage(rules map[string]bool) *YaraStage {
	return &YaraStage{rules: rules}
}

func (s *YaraStage) Name() string { return "YARA" }
func (s *YaraStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if e.Type == "process" && s.rules[e.BinaryPath] {
		ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
			EngineName: "YARA",
			Severity:   8.0,
			Weight:     0.8,
			MITREIDs:   []string{"T1059"},
		})
		ctxData.Matches = append(ctxData.Matches, "YARA rule matched binary path signature")
	}
	return nil
}

type SigmaStage struct {
	patterns []string
}

func NewSigmaStage(patterns []string) *SigmaStage {
	return &SigmaStage{patterns: patterns}
}

func (s *SigmaStage) Name() string { return "Sigma" }
func (s *SigmaStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	for _, pat := range s.patterns {
		if strings.Contains(e.CommandLine, pat) {
			ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
				EngineName: "Sigma",
				Severity:   7.0,
				Weight:     0.8,
				MITREIDs:   []string{"T1059"},
			})
			ctxData.Matches = append(ctxData.Matches, "Sigma behavioral match: "+pat)
			break
		}
	}
	return nil
}

type ThreatIntelStage struct {
	indicators map[string]bool
}

func NewThreatIntelStage(indicators map[string]bool) *ThreatIntelStage {
	return &ThreatIntelStage{indicators: indicators}
}

func (s *ThreatIntelStage) Name() string { return "ThreatIntelligence" }
func (s *ThreatIntelStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if s.indicators[e.RemoteIP] {
		ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
			EngineName: "ThreatIntelligence",
			Severity:   9.0,
			Weight:     0.9,
			MITREIDs:   []string{"T1071.001"},
		})
		ctxData.Matches = append(ctxData.Matches, "Matched known malicious destination IP")
	}
	return nil
}

type CorrelationStage struct{}

func (s *CorrelationStage) Name() string { return "Correlation" }
func (s *CorrelationStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if len(ctxData.EngineResults) >= 2 {
		ctxData.EngineResults = append(ctxData.EngineResults, scoring.EngineResult{
			EngineName: "Correlation",
			Severity:   5.0,
			Weight:     0.5,
			MITREIDs:   []string{"T1059"},
		})
		ctxData.Matches = append(ctxData.Matches, "Multi-stage engine correlation detected")
	}
	return nil
}

type RiskScoringStage struct {
	threshold float64
}

func NewRiskScoringStage(threshold float64) *RiskScoringStage {
	return &RiskScoringStage{threshold: threshold}
}

func (s *RiskScoringStage) Name() string { return "RiskScoring" }
func (s *RiskScoringStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if len(ctxData.EngineResults) == 0 {
		return nil
	}
	score := scoring.CalculateCompoundScore(ctxData.EngineResults)
	alert := scoring.GenerateAlert(ctxData.EngineResults)
	ctxData.AlertDetail = alert
	if score >= s.threshold {
		ctxData.AlertTriggered = true
	}
	return nil
}

type AlertStage struct {
	alertsChannel chan scoring.Alert
}

func NewAlertStage(alertsChannel chan scoring.Alert) *AlertStage {
	return &AlertStage{alertsChannel: alertsChannel}
}

func (s *AlertStage) Name() string { return "Alert" }
func (s *AlertStage) Process(ctx context.Context, e *telemetry.Event, ctxData *DetectionContext) error {
	if ctxData.AlertTriggered {
		select {
		case s.alertsChannel <- ctxData.AlertDetail:
		default:
		}
	}
	return nil
}
