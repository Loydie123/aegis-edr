package sigma

import (
	"gopkg.in/yaml.v3"
)

type Rule struct {
	Title       string               `yaml:"title"`
	Description string               `yaml:"description"`
	Logsource   Logsource            `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
}

type Logsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) AddRule(content []byte) error {
	var rule Rule
	if err := yaml.Unmarshal(content, &rule); err != nil {
		return err
	}
	e.rules = append(e.rules, rule)
	return nil
}

func (e *Engine) Evaluate(eventMap map[string]interface{}) []string {
	var matchedRules []string

	for _, rule := range e.rules {
		if rule.Logsource.Category != "" {
			cat, ok := eventMap["category"].(string)
			if !ok || cat != rule.Logsource.Category {
				continue
			}
		}

		matched := true
		for key, val := range rule.Detection {
			if key == "condition" {
				continue
			}

			expectedList, isSlice := val.([]interface{})
			if isSlice {
				fieldVal, ok := eventMap[key].(string)
				if !ok {
					matched = false
					break
				}
				anyMatch := false
				for _, expected := range expectedList {
					if expectedStr, ok := expected.(string); ok && expectedStr == fieldVal {
						anyMatch = true
						break
					}
				}
				if !anyMatch {
					matched = false
					break
				}
			} else if expectedStr, ok := val.(string); ok {
				fieldVal, ok := eventMap[key].(string)
				if !ok || fieldVal != expectedStr {
					matched = false
					break
				}
			} else {
				matched = false
				break
			}
		}

		if matched {
			matchedRules = append(matchedRules, rule.Title)
		}
	}

	return matchedRules
}
