package core

import (
	"os"
	"os/signal"
	"syscall"

	"aegis-edr/internal/logger"
)

type Bootstrap struct {
	Container *DIContainer
	LM        *LifecycleManager
	SM        *ServiceManager
}

func NewBootstrap() *Bootstrap {
	return &Bootstrap{
		Container: NewDIContainer(),
		LM:        NewLifecycleManager(),
		SM:        NewServiceManager(),
	}
}

func (b *Bootstrap) Initialize() error {
	diag := NewStartupDiagnostics()
	if err := diag.Run(); err != nil {
		logger.Log.Error("Startup diagnostics failed", "error", err)
		return err
	}
	Register(b.Container, b.LM)
	Register(b.Container, b.SM)
	return nil
}

func (b *Bootstrap) Run() {
	b.LM.SetState(StateRunning)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	<-sigs
	b.LM.SetState(StateStopping)
	b.LM.TriggerShutdown()
}
