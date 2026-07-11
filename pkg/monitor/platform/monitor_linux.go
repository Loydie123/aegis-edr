//go:build linux

package platform

import (
	"aegis-edr/pkg/monitor/eventrouter"
)

type LinuxProcessMonitor struct {
	router *eventrouter.Router
}

func newProcessMonitor() ProcessMonitor {
	return &LinuxProcessMonitor{}
}

func (m *LinuxProcessMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *LinuxProcessMonitor) Stop() error {
	return nil
}

type LinuxFileMonitor struct {
	router *eventrouter.Router
}

func newFileMonitor() FileMonitor {
	return &LinuxFileMonitor{}
}

func (m *LinuxFileMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *LinuxFileMonitor) Stop() error {
	return nil
}
