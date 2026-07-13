package core

import (
	"runtime"
)

type HealthSubsystem struct {
	sm *ServiceManager
}

func NewHealthSubsystem(sm *ServiceManager) *HealthSubsystem {
	return &HealthSubsystem{sm: sm}
}

type HealthReport struct {
	OverallStatus string
	NumGoroutines int
	AllocatedMem  uint64
}

func (hs *HealthSubsystem) Check() HealthReport {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return HealthReport{
		OverallStatus: "OK",
		NumGoroutines: runtime.NumGoroutine(),
		AllocatedMem:  ms.Alloc,
	}
}
