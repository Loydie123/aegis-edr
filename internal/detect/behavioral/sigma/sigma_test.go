package sigma

import (
	"testing"
)

func TestSigmaEngine(t *testing.T) {
	t.Parallel()

	ruleContent := []byte(`
title: Suspicious Process Spawning cmd.exe
description: Detects spawning of cmd.exe from web servers.
logsource:
  category: process
detection:
  parent_path: "/usr/sbin/nginx"
  image: "/bin/sh"
  condition: selection
`)

	engine := NewEngine()
	if err := engine.AddRule(ruleContent); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	matchingEvent := map[string]interface{}{
		"category":    "process",
		"parent_path": "/usr/sbin/nginx",
		"image":       "/bin/sh",
	}

	matches := engine.Evaluate(matchingEvent)
	if len(matches) != 1 || matches[0] != "Suspicious Process Spawning cmd.exe" {
		t.Errorf("expected match, got %v", matches)
	}

	nonMatchingEvent := map[string]interface{}{
		"category":    "process",
		"parent_path": "/usr/bin/bash",
		"image":       "/bin/sh",
	}

	matches = engine.Evaluate(nonMatchingEvent)
	if len(matches) != 0 {
		t.Errorf("expected no match, got %v", matches)
	}
}
