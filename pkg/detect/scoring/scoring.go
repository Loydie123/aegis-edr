package scoring

import (
	"math"
)

type EngineResult struct {
	EngineName string
	Severity   float64
	Weight     float64
	MITREIDs   []string
}

type Alert struct {
	CompoundScore float64
	TriggeredBy   []string
	MITRETags     []string
}

func CalculateCompoundScore(results []EngineResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	product := 1.0
	for _, res := range results {
		sev := math.Max(0.0, math.Min(1.0, res.Severity))
		weight := math.Max(0.0, math.Min(1.0, res.Weight))
		product *= (1.0 - (sev * weight))
	}

	return 1.0 - product
}

func GenerateAlert(results []EngineResult) Alert {
	score := CalculateCompoundScore(results)

	var triggers []string
	mitreMap := make(map[string]bool)

	for _, res := range results {
		triggers = append(triggers, res.EngineName)
		for _, id := range res.MITREIDs {
			mitreMap[id] = true
		}
	}

	var mitreTags []string
	for id := range mitreMap {
		mitreTags = append(mitreTags, id)
	}

	return Alert{
		CompoundScore: score,
		TriggeredBy:   triggers,
		MITRETags:     mitreTags,
	}
}
