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
