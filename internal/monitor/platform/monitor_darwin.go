//go:build darwin

package platform

import (
	"aegis-edr/internal/core"
	"aegis-edr/internal/eventrouter"
)

type DarwinProcessMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newProcessMonitor() ProcessMonitor {
	return &DarwinProcessMonitor{}
}

func (m *DarwinProcessMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinProcessMonitor) Stop() error {
	return nil
}

type DarwinFileMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newFileMonitor() FileMonitor {
	return &DarwinFileMonitor{}
}

func (m *DarwinFileMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinFileMonitor) Stop() error {
	return nil
}

type DarwinNetworkMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newNetworkMonitor() NetworkMonitor {
	return &DarwinNetworkMonitor{}
}

func (m *DarwinNetworkMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinNetworkMonitor) Stop() error {
	return nil
}

type DarwinRegistryMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newRegistryMonitor() RegistryMonitor {
	return &DarwinRegistryMonitor{}
}

func (m *DarwinRegistryMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinRegistryMonitor) Stop() error {
	return nil
}

type DarwinServiceMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newServiceMonitor() ServiceMonitor {
	return &DarwinServiceMonitor{}
}

func (m *DarwinServiceMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinServiceMonitor) Stop() error {
	return nil
}

type DarwinDriverMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newDriverMonitor() DriverMonitor {
	return &DarwinDriverMonitor{}
}

func (m *DarwinDriverMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinDriverMonitor) Stop() error {
	return nil
}

type DarwinUsbMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newUsbMonitor() UsbMonitor {
	return &DarwinUsbMonitor{}
}

func (m *DarwinUsbMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinUsbMonitor) Stop() error {
	return nil
}

type DarwinScheduledTaskMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newScheduledTaskMonitor() ScheduledTaskMonitor {
	return &DarwinScheduledTaskMonitor{}
}

func (m *DarwinScheduledTaskMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinScheduledTaskMonitor) Stop() error {
	return nil
}

type DarwinStartupMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newStartupMonitor() StartupMonitor {
	return &DarwinStartupMonitor{}
}

func (m *DarwinStartupMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *DarwinStartupMonitor) Stop() error {
	return nil
}
