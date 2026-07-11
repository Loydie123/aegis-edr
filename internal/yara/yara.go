package yara

import (
	"errors"

	yaraLib "github.com/hillu/go-yara/v4"
)

type Engine struct {
	rules *yaraLib.Rules
}

func NewEngine(rulesContent string) (*Engine, error) {
	c, err := yaraLib.NewCompiler()
	if err != nil {
		return nil, err
	}
	defer c.Destroy()

	if err := c.AddString(rulesContent, ""); err != nil {
		return nil, err
	}

	rules, err := c.GetRules()
	if err != nil {
		return nil, err
	}

	return &Engine{rules: rules}, nil
}

func (e *Engine) ScanBytes(data []byte) ([]string, error) {
	if e.rules == nil {
		return nil, errors.New("engine rules not initialized")
	}

	var matches yaraLib.MatchRules
	s, err := yaraLib.NewScanner(e.rules)
	if err != nil {
		return nil, err
	}

	s.SetCallback(&matches)

	if err := s.ScanMem(data); err != nil {
		return nil, err
	}

	var ruleNames []string
	for _, m := range matches {
		ruleNames = append(ruleNames, m.Rule)
	}

	return ruleNames, nil
}
