package core

import (
	"context"
	"sync"
)

type ServiceStatus string

const (
	StatusStopped  ServiceStatus = "STOPPED"
	StatusStarting ServiceStatus = "STARTING"
	StatusRunning  ServiceStatus = "RUNNING"
	StatusStopping ServiceStatus = "STOPPING"
	StatusFailed   ServiceStatus = "FAILED"
)

type AegisService interface {
	Start(ctx context.Context) error
	Stop() error
	Status() ServiceStatus
}

type ServiceManager struct {
	mu       sync.RWMutex
	services map[string]AegisService
}

func NewServiceManager() *ServiceManager {
	return &ServiceManager{
		services: make(map[string]AegisService),
	}
}

func (sm *ServiceManager) Register(name string, service AegisService) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.services[name] = service
}

func (sm *ServiceManager) StartAll(ctx context.Context) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, service := range sm.services {
		if err := service.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (sm *ServiceManager) StopAll() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, service := range sm.services {
		_ = service.Stop()
	}
}

func (sm *ServiceManager) GetStatus(name string) (ServiceStatus, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	srv, exists := sm.services[name]
	if !exists {
		return StatusStopped, false
	}
	return srv.Status(), true
}
