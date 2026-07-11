package api

import (
	"context"
	"errors"
	"time"

	"aegis-edr/internal/forensics"
	"aegis-edr/internal/storage"
)

type ProcessKiller interface {
	KillTree(pid int) error
}

type NetworkIsolator interface {
	IsolateHost() error
	RestoreHost() error
}

type Quarantiner interface {
	QuarantineFile(src, destDir string) error
}

type Server struct {
	UnimplementedAegisServiceServer
	store       *storage.Storage
	killer      ProcessKiller
	isolator    NetworkIsolator
	quarantiner Quarantiner
}

func NewServer(store *storage.Storage, killer ProcessKiller, isolator NetworkIsolator, quarantiner Quarantiner) *Server {
	return &Server{
		store:       store,
		killer:      killer,
		isolator:    isolator,
		quarantiner: quarantiner,
	}
}

func (s *Server) GetStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	return &StatusResponse{
		Version: "1.0.0-Beta",
		Status:  "RUNNING",
	}, nil
}

func (s *Server) RunScan(req *ScanRequest, stream AegisService_RunScanServer) error {
	return nil
}

func (s *Server) TriggerResponse(ctx context.Context, req *ResponseRequest) (*ResponseResponse, error) {
	if s.killer == nil || s.isolator == nil || s.quarantiner == nil {
		return nil, errors.New("containment engines not initialized")
	}

	switch req.Action {
	case "kill":
		if req.TargetPid <= 0 {
			return nil, errors.New("invalid target PID")
		}
		if err := s.killer.KillTree(int(req.TargetPid)); err != nil {
			return nil, err
		}
		return &ResponseResponse{
			Success:        true,
			Message:        "Process tree terminated successfully",
			ActionExecuted: "kill",
		}, nil

	case "isolate":
		if err := s.isolator.IsolateHost(); err != nil {
			return nil, err
		}
		return &ResponseResponse{
			Success:        true,
			Message:        "Host network isolated successfully",
			ActionExecuted: "isolate",
		}, nil

	case "restore":
		if err := s.isolator.RestoreHost(); err != nil {
			return nil, err
		}
		return &ResponseResponse{
			Success:        true,
			Message:        "Host network restored successfully",
			ActionExecuted: "restore",
		}, nil

	case "quarantine":
		if req.TargetFile == "" {
			return nil, errors.New("target file path is required")
		}
		if err := s.quarantiner.QuarantineFile(req.TargetFile, "/var/lib/aegis/quarantine"); err != nil {
			return nil, err
		}
		return &ResponseResponse{
			Success:        true,
			Message:        "File placed in quarantine successfully",
			ActionExecuted: "quarantine",
		}, nil

	default:
		return nil, errors.New("unsupported action type")
	}
}

func (s *Server) GetTimeline(req *TimelineRequest, stream AegisService_GetTimelineServer) error {
	if s.store == nil {
		return errors.New("storage engine is not initialized")
	}

	start := time.Unix(req.StartTimeEpoch, 0)
	end := time.Unix(req.EndTimeEpoch, 0)

	builder := forensics.NewTimelineBuilder(s.store)
	events, err := builder.BuildTimeline(start, end)
	if err != nil {
		return err
	}

	for _, ev := range events {
		pbEvent := &TimelineEvent{
			Timestamp:   ev.Timestamp.Format(time.RFC3339),
			Category:    ev.Category,
			Description: ev.Description,
			RiskScore:   0.0,
		}
		if err := stream.Send(pbEvent); err != nil {
			return err
		}
	}

	return nil
}
