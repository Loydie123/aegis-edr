package core

import (
	"context"
	"testing"
	"time"
)

type dummyService struct {
	status ServiceStatus
}

func (d *dummyService) Start(ctx context.Context) error {
	d.status = StatusRunning
	return nil
}

func (d *dummyService) Stop() error {
	d.status = StatusStopped
	return nil
}

func (d *dummyService) Status() ServiceStatus {
	return d.status
}

func TestDIContainer(t *testing.T) {
	c := NewDIContainer()
	s := &dummyService{}

	Register(c, s)
	resolved, err := Resolve[*dummyService](c)
	if err != nil {
		t.Fatalf("failed to resolve service: %v", err)
	}

	if resolved != s {
		t.Error("resolved instance mismatch")
	}
}

func TestLifecycleManager(t *testing.T) {
	lm := NewLifecycleManager()
	if lm.GetState() != StateInitializing {
		t.Errorf("expected INITIALIZING, got %v", lm.GetState())
	}

	lm.SetState(StateRunning)
	if lm.GetState() != StateRunning {
		t.Errorf("expected RUNNING, got %v", lm.GetState())
	}

	hookExecuted := false
	lm.RegisterShutdownHook(func() {
		hookExecuted = true
	})

	lm.TriggerShutdown()
	if !hookExecuted {
		t.Error("expected shutdown hook execution")
	}

	if lm.GetState() != StateStopped {
		t.Errorf("expected STOPPED, got %v", lm.GetState())
	}
}

func TestServiceManager(t *testing.T) {
	sm := NewServiceManager()
	s := &dummyService{}

	sm.Register("dummy", s)
	if err := sm.StartAll(context.Background()); err != nil {
		t.Fatalf("failed to start services: %v", err)
	}

	status, ok := sm.GetStatus("dummy")
	if !ok || status != StatusRunning {
		t.Errorf("expected RUNNING, got %v", status)
	}

	sm.StopAll()
	status, _ = sm.GetStatus("dummy")
	if status != StatusStopped {
		t.Errorf("expected STOPPED, got %v", status)
	}
}

func TestEventBus(t *testing.T) {
	eb := NewEventBus()
	ch := eb.Subscribe("alerts")

	eb.Publish(Event{Topic: "alerts", Data: "critical-threat"})

	select {
	case ev := <-ch:
		if ev.Data != "critical-threat" {
			t.Errorf("expected critical-threat, got %v", ev.Data)
		}
	case <-time.After(1 * time.Second):
		t.Error("expected event publish timeout")
	}
}

func TestDiagnosticsAndHealth(t *testing.T) {
	diag := NewStartupDiagnostics()
	if err := diag.Run(); err != nil {
		t.Fatalf("diagnostics run failed: %v", err)
	}

	sm := NewServiceManager()
	hs := NewHealthSubsystem(sm)
	report := hs.Check()

	if report.OverallStatus != "OK" {
		t.Errorf("expected overall OK status, got %s", report.OverallStatus)
	}
}
