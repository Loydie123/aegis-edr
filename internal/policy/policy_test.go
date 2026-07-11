package policy

import (
	"context"
	"testing"

	"aegis-edr/internal/config"
)

func TestPolicyEngineMitigation(t *testing.T) {
	cfg := &config.ResponseConfig{
		AutoMitigation: true,
		RiskThreshold:  0.8,
		Actions: []config.ActionConfig{
			{Name: "isolate", Enabled: true},
			{Name: "kill", Enabled: true},
		},
	}

	pe := NewPolicyEngine(cfg)

	msg, err := pe.EvaluateAndMitigate(context.Background(), 0.5, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "score 0.50 below risk threshold 0.80" {
		t.Errorf("unexpected message: %s", msg)
	}

	disabledCfg := &config.ResponseConfig{
		AutoMitigation: false,
	}
	peDisabled := NewPolicyEngine(disabledCfg)
	msg, err = peDisabled.EvaluateAndMitigate(context.Background(), 0.9, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "auto-mitigation disabled" {
		t.Errorf("unexpected message: %s", msg)
	}
}
