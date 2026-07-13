//go:build linux

package platform

import (
	"aegis-edr/internal/core"
	"aegis-edr/internal/eventrouter"
)

type LinuxProcessMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newProcessMonitor() ProcessMonitor {
	return &LinuxProcessMonitor{}
}

func (m *LinuxProcessMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxProcessMonitor) Stop() error {
	return nil
}

type LinuxFileMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newFileMonitor() FileMonitor {
	return &LinuxFileMonitor{}
}

func (m *LinuxFileMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxFileMonitor) Stop() error {
	return nil
}

type LinuxNetworkMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newNetworkMonitor() NetworkMonitor {
	return &LinuxNetworkMonitor{}
}

func (m *LinuxNetworkMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxNetworkMonitor) Stop() error {
	return nil
}

type LinuxRegistryMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newRegistryMonitor() RegistryMonitor {
	return &LinuxRegistryMonitor{}
}

func (m *LinuxRegistryMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxRegistryMonitor) Stop() error {
	return nil
}

type LinuxServiceMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newServiceMonitor() ServiceMonitor {
	return &LinuxServiceMonitor{}
}

func (m *LinuxServiceMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxServiceMonitor) Stop() error {
	return nil
}

type LinuxDriverMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newDriverMonitor() DriverMonitor {
	return &LinuxDriverMonitor{}
}

func (m *LinuxDriverMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxDriverMonitor) Stop() error {
	return nil
}

type LinuxUsbMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newUsbMonitor() UsbMonitor {
	return &LinuxUsbMonitor{}
}

func (m *LinuxUsbMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxUsbMonitor) Stop() error {
	return nil
}

type LinuxScheduledTaskMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newScheduledTaskMonitor() ScheduledTaskMonitor {
	return &LinuxScheduledTaskMonitor{}
}

func (m *LinuxScheduledTaskMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxScheduledTaskMonitor) Stop() error {
	return nil
}

type LinuxStartupMonitor struct {
	router *eventrouter.Router
	eb     *core.EventBus
}

func newStartupMonitor() StartupMonitor {
	return &LinuxStartupMonitor{}
}

func (m *LinuxStartupMonitor) Start(router *eventrouter.Router, eb *core.EventBus) error {
	m.router = router
	m.eb = eb
	return nil
}

func (m *LinuxStartupMonitor) Stop() error {
	return nil
}
