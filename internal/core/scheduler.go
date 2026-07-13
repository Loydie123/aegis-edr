package core

import (
	"context"
	"time"

	"aegis-edr/internal/logger"
)

type Scheduler struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewScheduler(parentCtx context.Context) *Scheduler {
	ctx, cancel := context.WithCancel(parentCtx)
	return &Scheduler{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Scheduler) Schedule(interval time.Duration, task func()) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runTask(task)
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

func (s *Scheduler) runTask(task func()) {
	defer func() {
		if r := recover(); r != nil {
			logger.Log.Error("scheduler task panicked", "error", r)
		}
	}()
	task()
}

func (s *Scheduler) Stop() {
	s.cancel()
}
