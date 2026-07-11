//go:build windows

package platform

import (
	"aegis-edr/pkg/monitor/eventrouter"
)

type WindowsProcessMonitor struct {
	router *eventrouter.Router
}

func newProcessMonitor() ProcessMonitor {
	return &WindowsProcessMonitor{}
}

func (m *WindowsProcessMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *WindowsProcessMonitor) Stop() error {
	return nil
}

type WindowsFileMonitor struct {
	router *eventrouter.Router
}

func newFileMonitor() FileMonitor {
	return &WindowsFileMonitor{}
}

func (m *WindowsFileMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *WindowsFileMonitor) Stop() error {
	return nil
}
