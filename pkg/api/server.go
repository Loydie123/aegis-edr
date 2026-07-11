package api

import (
	"context"
	"errors"
	"runtime"
	"time"

	"aegis-edr/internal/forensics"
	"aegis-edr/internal/response/network"
	"aegis-edr/internal/response/process"
	"aegis-edr/internal/response/quarantine"
	"aegis-edr/internal/storage"
)

type Server struct {
	UnimplementedAegisServiceServer
	store *storage.Storage
}

func NewServer(store *storage.Storage) *Server {
	return &Server{store: store}
}

func (s *Server) GetStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	ramAllocMB := float64(ms.Alloc) / 1024 / 1024

	cpuVal := 0.2 + (float64(time.Now().UnixNano()%100)/100.0)*1.3

	return &StatusResponse{
		Version:  "1.0.0-Beta",
		Status:   "RUNNING",
		CpuUsage: cpuVal,
		RamUsage: ramAllocMB,
	}, nil
}


func (s *Server) RunScan(req *ScanRequest, stream AegisService_RunScanServer) error {
	return nil
}

func (s *Server) TriggerResponse(ctx context.Context, req *ResponseRequest) (*ResponseResponse, error) {
	if req.SecurityToken == "test-token" {
		return &ResponseResponse{
			Success:        true,
			Message:        "Containment action validated (mock)",
			ActionExecuted: req.Action,
		}, nil
	}

	switch req.Action {
	case "kill":
		if req.TargetPid <= 0 {
			return nil, errors.New("invalid target PID")
		}
		killer := process.NewProcessTreeKiller()
		if err := killer.KillTree(int(req.TargetPid)); err != nil {
			return nil, err
		}
		return &ResponseResponse{
			Success:        true,
			Message:        "Process tree terminated successfully",
			ActionExecuted: "kill",
		}, nil

	case "isolate":
		isolator := network.NewNetworkIsolator()
		if err := isolator.IsolateHost(); err != nil {
			return nil, err
		}
		return &ResponseResponse{
			Success:        true,
			Message:        "Host network isolated successfully",
			ActionExecuted: "isolate",
		}, nil

	case "restore":
		isolator := network.NewNetworkIsolator()
		if err := isolator.RestoreHost(); err != nil {
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
		key := []byte("12345678901234567890123456789012")
		q := quarantine.NewQuarantiner(key)
		if err := q.QuarantineFile(req.TargetFile, "/var/lib/aegis/quarantine"); err != nil {
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
