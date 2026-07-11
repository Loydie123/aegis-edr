//go:build darwin

package platform

import (
	"aegis-edr/pkg/monitor/eventrouter"
)

type DarwinProcessMonitor struct {
	router *eventrouter.Router
}

func newProcessMonitor() ProcessMonitor {
	return &DarwinProcessMonitor{}
}

func (m *DarwinProcessMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *DarwinProcessMonitor) Stop() error {
	return nil
}
