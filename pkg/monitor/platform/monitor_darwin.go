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

type DarwinFileMonitor struct {
	router *eventrouter.Router
}

func newFileMonitor() FileMonitor {
	return &DarwinFileMonitor{}
}

func (m *DarwinFileMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *DarwinFileMonitor) Stop() error {
	return nil
}

type DarwinNetworkMonitor struct {
	router *eventrouter.Router
}

func newNetworkMonitor() NetworkMonitor {
	return &DarwinNetworkMonitor{}
}

func (m *DarwinNetworkMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *DarwinNetworkMonitor) Stop() error {
	return nil
}

type DarwinRegistryMonitor struct {
	router *eventrouter.Router
}

func newRegistryMonitor() RegistryMonitor {
	return &DarwinRegistryMonitor{}
}

func (m *DarwinRegistryMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *DarwinRegistryMonitor) Stop() error {
	return nil
}
