package yara

import (
	"testing"
)

func TestYaraScan(t *testing.T) {
	t.Parallel()

	rule := `
rule TestRule {
    strings:
        $a = "malicious_payload"
    condition:
        $a
}`

	engine, err := NewEngine(rule)
	if err != nil {
		t.Fatalf("failed to compile rule: %v", err)
	}

	benign := []byte("this is a benign string with no payload")
	matches, err := engine.ScanBytes(benign)
	if err != nil {
		t.Fatalf("failed to scan benign data: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for benign data, got %d", len(matches))
	}

	malicious := []byte("some header info malicious_payload some tail info")
	matches, err = engine.ScanBytes(malicious)
	if err != nil {
		t.Fatalf("failed to scan malicious data: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 match for malicious data, got %d", len(matches))
	}
	if matches[0] != "TestRule" {
		t.Errorf("expected match TestRule, got %s", matches[0])
	}
}
