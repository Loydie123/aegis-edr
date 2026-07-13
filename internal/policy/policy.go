package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"aegis-edr/internal/config"
	"aegis-edr/internal/response/network"
	"aegis-edr/internal/response/process"
	"aegis-edr/internal/response/quarantine"
)

type PolicyAction string

const (
	ActionAllow   PolicyAction = "Allow"
	ActionDeny    PolicyAction = "Deny"
	ActionMonitor PolicyAction = "Monitor"
	ActionAudit   PolicyAction = "Audit"
	ActionIgnore  PolicyAction = "Ignore"
)

type Rule struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Action      PolicyAction `json:"action"`
	ProcessPath string       `json:"process_path"`
	RiskScore   float64      `json:"risk_score"`
}

type Policy struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id"`
	Rules    []Rule `json:"rules"`
	Version  int    `json:"version"`
}

type PolicyEngine struct {
	mu             sync.RWMutex
	cfg            *config.ResponseConfig
	policies       map[string]*Policy
	activePolicyID string
}

func NewPolicyEngine(cfg *config.ResponseConfig) *PolicyEngine {
	return &PolicyEngine{
		cfg:      cfg,
		policies: make(map[string]*Policy),
	}
}

func (pe *PolicyEngine) ValidatePolicy(p *Policy) error {
	if p.ID == "" {
		return errors.New("policy ID cannot be empty")
	}

	for _, rule := range p.Rules {
		if rule.ID == "" {
			return errors.New("rule ID cannot be empty")
		}
		act := rule.Action
		if act != ActionAllow && act != ActionDeny && act != ActionMonitor && act != ActionAudit && act != ActionIgnore {
			return fmt.Errorf("invalid policy action: %s", act)
		}
		if rule.ProcessPath == "" {
			return errors.New("rule process path cannot be empty")
		}
	}
	return nil
}

func (pe *PolicyEngine) LoadPolicy(p *Policy) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if err := pe.ValidatePolicy(p); err != nil {
		return err
	}

	pe.policies[p.ID] = p
	return nil
}

func (pe *PolicyEngine) SetActivePolicy(id string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, exists := pe.policies[id]; !exists {
		return fmt.Errorf("policy %s not loaded", id)
	}

	pe.activePolicyID = id
	return nil
}

func (pe *PolicyEngine) EvaluateRule(processPath string) PolicyAction {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	if pe.activePolicyID == "" {
		return ActionMonitor
	}

	return pe.evaluateChain(pe.activePolicyID, processPath)
}

func (pe *PolicyEngine) evaluateChain(policyID string, processPath string) PolicyAction {
	p, exists := pe.policies[policyID]
	if !exists {
		return ActionMonitor
	}

	for _, r := range p.Rules {
		if strings.Contains(processPath, r.ProcessPath) {
			return r.Action
		}
	}

	if p.ParentID != "" {
		return pe.evaluateChain(p.ParentID, processPath)
	}

	return ActionMonitor
}

func (pe *PolicyEngine) EvaluateAndMitigate(ctx context.Context, score float64, details map[string]interface{}) (string, error) {
	if pe.cfg == nil || !pe.cfg.AutoMitigation {
		return "auto-mitigation disabled", nil
	}

	if score < pe.cfg.RiskThreshold {
		return fmt.Sprintf("score %.2f below risk threshold %.2f", score, pe.cfg.RiskThreshold), nil
	}

	var actionsExecuted []string
	for _, action := range pe.cfg.Actions {
		if !action.Enabled {
			continue
		}

		switch action.Name {
		case "kill":
			pidVal, ok := details["pid"]
			if !ok {
				continue
			}
			pid, isInt := pidVal.(int)
			if !isInt {
				continue
			}
			killer := process.NewProcessTreeKiller()
			if err := killer.KillTree(pid); err != nil {
				return "", fmt.Errorf("failed to execute auto-kill: %w", err)
			}
			actionsExecuted = append(actionsExecuted, "kill")

		case "isolate":
			isolator := network.NewNetworkIsolator()
			if err := isolator.IsolateHost(); err != nil {
				return "", fmt.Errorf("failed to execute auto-isolate: %w", err)
			}
			actionsExecuted = append(actionsExecuted, "isolate")

		case "quarantine":
			fileVal, ok := details["filepath"]
			if !ok {
				continue
			}
			filepath, isStr := fileVal.(string)
			if !isStr {
				continue
			}
			key := []byte("12345678901234567890123456789012")
			q := quarantine.NewQuarantiner(key)
			if err := q.QuarantineFile(filepath, "/var/lib/aegis/quarantine"); err != nil {
				return "", fmt.Errorf("failed to execute auto-quarantine: %w", err)
			}
			actionsExecuted = append(actionsExecuted, "quarantine")
		}
	}

	if len(actionsExecuted) == 0 {
		return "no matching actions executed", nil
	}

	return fmt.Sprintf("auto-mitigation executed actions: %v", actionsExecuted), nil
}
