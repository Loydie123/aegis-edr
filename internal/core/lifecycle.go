package core

import (
	"sync"
)

type AppState string

const (
	StateInitializing AppState = "INITIALIZING"
	StateRunning      AppState = "RUNNING"
	StateStopping     AppState = "STOPPING"
	StateStopped      AppState = "STOPPED"
)

type LifecycleManager struct {
	mu            sync.RWMutex
	state         AppState
	shutdownHooks []func()
}

func NewLifecycleManager() *LifecycleManager {
	return &LifecycleManager{
		state: StateInitializing,
	}
}

func (lm *LifecycleManager) GetState() AppState {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.state
}

func (lm *LifecycleManager) SetState(state AppState) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.state = state
}

func (lm *LifecycleManager) RegisterShutdownHook(hook func()) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.shutdownHooks = append(lm.shutdownHooks, hook)
}

func (lm *LifecycleManager) TriggerShutdown() {
	lm.mu.Lock()
	lm.state = StateStopping
	hooks := lm.shutdownHooks
	lm.mu.Unlock()

	for _, hook := range hooks {
		hook()
	}

	lm.mu.Lock()
	lm.state = StateStopped
	lm.mu.Unlock()
}
