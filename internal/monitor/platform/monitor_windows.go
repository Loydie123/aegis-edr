//go:build windows

package platform

import (
	"aegis-edr/internal/monitor/eventrouter"
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

type WindowsNetworkMonitor struct {
	router *eventrouter.Router
}

func newNetworkMonitor() NetworkMonitor {
	return &WindowsNetworkMonitor{}
}

func (m *WindowsNetworkMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *WindowsNetworkMonitor) Stop() error {
	return nil
}

type WindowsRegistryMonitor struct {
	router *eventrouter.Router
}

func newRegistryMonitor() RegistryMonitor {
	return &WindowsRegistryMonitor{}
}

func (m *WindowsRegistryMonitor) Start(router *eventrouter.Router) error {
	m.router = router
	return nil
}

func (m *WindowsRegistryMonitor) Stop() error {
	return nil
}
