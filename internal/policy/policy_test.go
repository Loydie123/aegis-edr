package policy

import (
	"testing"

	"aegis-edr/internal/config"
)

func TestPolicyEngineValidation(t *testing.T) {
	pe := NewPolicyEngine(&config.ResponseConfig{})

	// Valid policy
	p1 := &Policy{
		ID: "p1",
		Rules: []Rule{
			{ID: "r1", Name: "Allow cmd", Action: ActionAllow, ProcessPath: "cmd.exe"},
		},
	}
	if err := pe.ValidatePolicy(p1); err != nil {
		t.Errorf("expected p1 to be valid, got: %v", err)
	}

	// Invalid policy: empty path
	p2 := &Policy{
		ID: "p2",
		Rules: []Rule{
			{ID: "r2", Name: "Deny evil", Action: ActionDeny, ProcessPath: ""},
		},
	}
	if err := pe.ValidatePolicy(p2); err == nil {
		t.Error("expected p2 (empty path) to be invalid")
	}

	// Invalid policy: invalid action
	p3 := &Policy{
		ID: "p3",
		Rules: []Rule{
			{ID: "r3", Name: "Bypass", Action: "BypassAction", ProcessPath: "cmd.exe"},
		},
	}
	if err := pe.ValidatePolicy(p3); err == nil {
		t.Error("expected p3 (invalid action) to be invalid")
	}
}

func TestPolicyInheritance(t *testing.T) {
	pe := NewPolicyEngine(&config.ResponseConfig{})

	// Parent Policy
	parent := &Policy{
		ID: "parent",
		Rules: []Rule{
			{ID: "r1", Name: "Deny malware", Action: ActionDeny, ProcessPath: "malware.exe"},
			{ID: "r2", Name: "Monitor sh", Action: ActionMonitor, ProcessPath: "sh"},
		},
	}
	_ = pe.LoadPolicy(parent)

	// Child Policy (Overrides r2 to Deny sh, inherits malware.exe rule)
	child := &Policy{
		ID:       "child",
		ParentID: "parent",
		Rules: []Rule{
			{ID: "r2-override", Name: "Deny sh", Action: ActionDeny, ProcessPath: "sh"},
		},
	}
	_ = pe.LoadPolicy(child)

	_ = pe.SetActivePolicy("child")

	// Overridden rule: should return Deny
	act := pe.EvaluateRule("sh")
	if act != ActionDeny {
		t.Errorf("expected overridden rule to evaluate to Deny, got: %s", act)
	}

	// Inherited rule: should return Deny
	act = pe.EvaluateRule("malware.exe")
	if act != ActionDeny {
		t.Errorf("expected inherited rule to evaluate to Deny, got: %s", act)
	}

	// Default fallback: should return Monitor
	act = pe.EvaluateRule("notepad.exe")
	if act != ActionMonitor {
		t.Errorf("expected default rule to evaluate to Monitor, got: %s", act)
	}
}
