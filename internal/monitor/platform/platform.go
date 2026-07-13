package platform

import (
	"aegis-edr/internal/core"
	"aegis-edr/internal/eventrouter"
)

type ProcessMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewProcessMonitor() ProcessMonitor {
	return newProcessMonitor()
}

type FileMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewFileMonitor() FileMonitor {
	return newFileMonitor()
}

type NetworkMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewNetworkMonitor() NetworkMonitor {
	return newNetworkMonitor()
}

type RegistryMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewRegistryMonitor() RegistryMonitor {
	return newRegistryMonitor()
}

type ServiceMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewServiceMonitor() ServiceMonitor {
	return newServiceMonitor()
}

type DriverMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewDriverMonitor() DriverMonitor {
	return newDriverMonitor()
}

type UsbMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewUsbMonitor() UsbMonitor {
	return newUsbMonitor()
}

type ScheduledTaskMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewScheduledTaskMonitor() ScheduledTaskMonitor {
	return newScheduledTaskMonitor()
}

type StartupMonitor interface {
	Start(router *eventrouter.Router, eb *core.EventBus) error
	Stop() error
}

func NewStartupMonitor() StartupMonitor {
	return newStartupMonitor()
}
