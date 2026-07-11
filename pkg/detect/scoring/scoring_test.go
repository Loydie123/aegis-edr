package scoring

import (
	"math"
	"testing"
)

func TestCalculateCompoundScore(t *testing.T) {
	t.Parallel()

	results := []EngineResult{
		{
			EngineName: "yara",
			Severity:   0.8,
			Weight:     0.9,
		},
		{
			EngineName: "heuristics",
			Severity:   0.7,
			Weight:     0.8,
		},
	}

	score := CalculateCompoundScore(results)
	expected := 0.8768
	if math.Abs(score-expected) > 1e-6 {
		t.Errorf("expected compound score %f, got %f", expected, score)
	}
}

func TestGenerateAlert(t *testing.T) {
	t.Parallel()

	results := []EngineResult{
		{
			EngineName: "yara",
			Severity:   0.8,
			Weight:     0.9,
			MITREIDs:   []string{"T1059", "T1106"},
		},
		{
			EngineName: "sigma",
			Severity:   0.6,
			Weight:     0.7,
			MITREIDs:   []string{"T1059", "T1083"},
		},
	}

	alert := GenerateAlert(results)

	if len(alert.TriggeredBy) != 2 {
		t.Errorf("expected 2 triggers, got %d", len(alert.TriggeredBy))
	}

	if len(alert.MITRETags) != 3 {
		t.Errorf("expected 3 deduplicated MITRE tags, got %d", len(alert.MITRETags))
	}

	tagMap := make(map[string]bool)
	for _, tag := range alert.MITRETags {
		tagMap[tag] = true
	}

	if !tagMap["T1059"] || !tagMap["T1106"] || !tagMap["T1083"] {
		t.Errorf("missing expected MITRE tags in map: %v", alert.MITRETags)
	}
}
