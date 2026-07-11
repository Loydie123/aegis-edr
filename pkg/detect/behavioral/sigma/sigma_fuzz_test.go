package sigma

import (
	"testing"
)

func FuzzAddRule(f *testing.F) {
	seeds := [][]byte{
		[]byte(`
title: Suspicious Process
logsource:
  category: process
detection:
  image: "/bin/sh"
`),
		[]byte(`invalid yaml content {:`),
		[]byte(``),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		e := NewEngine()
		_ = e.AddRule(data)
	})
}
