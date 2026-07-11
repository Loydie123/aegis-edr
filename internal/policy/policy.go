package policy

import (
	"context"
	"fmt"

	"aegis-edr/internal/config"
	"aegis-edr/internal/response/network"
	"aegis-edr/internal/response/process"
	"aegis-edr/internal/response/quarantine"
)

type PolicyEngine struct {
	cfg *config.ResponseConfig
}

func NewPolicyEngine(cfg *config.ResponseConfig) *PolicyEngine {
	return &PolicyEngine{cfg: cfg}
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
