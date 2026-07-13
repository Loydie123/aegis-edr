//go:build windows

package platform

import (
	"aegis-edr/internal/core"
	"aegis-edr/internal/eventrouter"
)

type WindowsProcessMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newProcessMonitor() ProcessMonitor {
	return &WindowsProcessMonitor{}
}

func (m *WindowsProcessMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsProcessMonitor) Stop() error {
	return nil
}

type WindowsFileMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newFileMonitor() FileMonitor {
	return &WindowsFileMonitor{}
}

func (m *WindowsFileMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsFileMonitor) Stop() error {
	return nil
}

type WindowsNetworkMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newNetworkMonitor() NetworkMonitor {
	return &WindowsNetworkMonitor{}
}

func (m *WindowsNetworkMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsNetworkMonitor) Stop() error {
	return nil
}

type WindowsRegistryMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newRegistryMonitor() RegistryMonitor {
	return &WindowsRegistryMonitor{}
}

func (m *WindowsRegistryMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsRegistryMonitor) Stop() error {
	return nil
}

type WindowsServiceMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newServiceMonitor() ServiceMonitor {
	return &WindowsServiceMonitor{}
}

func (m *WindowsServiceMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsServiceMonitor) Stop() error {
	return nil
}

type WindowsDriverMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newDriverMonitor() DriverMonitor {
	return &WindowsDriverMonitor{}
}

func (m *WindowsDriverMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsDriverMonitor) Stop() error {
	return nil
}

type WindowsUsbMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newUsbMonitor() UsbMonitor {
	return &WindowsUsbMonitor{}
}

func (m *WindowsUsbMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsUsbMonitor) Stop() error {
	return nil
}

type WindowsScheduledTaskMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newScheduledTaskMonitor() ScheduledTaskMonitor {
	return &WindowsScheduledTaskMonitor{}
}

func (m *WindowsScheduledTaskMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsScheduledTaskMonitor) Stop() error {
	return nil
}

type WindowsStartupMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newStartupMonitor() StartupMonitor {
	return &WindowsStartupMonitor{}
}

func (m *WindowsStartupMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *WindowsStartupMonitor) Stop() error {
	return nil
}
