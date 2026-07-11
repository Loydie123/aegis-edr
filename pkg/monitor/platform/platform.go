package platform

import (
	"aegis-edr/pkg/monitor/eventrouter"
)

type ProcessMonitor interface {
	Start(router *eventrouter.Router) error
	Stop() error
}

func NewProcessMonitor() ProcessMonitor {
	return newProcessMonitor()
}

type FileMonitor interface {
	Start(router *eventrouter.Router) error
	Stop() error
}

func NewFileMonitor() FileMonitor {
	return newFileMonitor()
}

type NetworkMonitor interface {
	Start(router *eventrouter.Router) error
	Stop() error
}

func NewNetworkMonitor() NetworkMonitor {
	return newNetworkMonitor()
}

type RegistryMonitor interface {
	Start(router *eventrouter.Router) error
	Stop() error
}

func NewRegistryMonitor() RegistryMonitor {
	return newRegistryMonitor()
}
