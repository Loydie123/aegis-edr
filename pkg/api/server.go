package api

import (
	"context"
	"errors"
	"time"

	"aegis-edr/internal/forensics"
	"aegis-edr/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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
	token       string
}

func NewServer(store *storage.Storage, killer ProcessKiller, isolator NetworkIsolator, quarantiner Quarantiner, token string) *Server {
	return &Server{
		store:       store,
		killer:      killer,
		isolator:    isolator,
		quarantiner: quarantiner,
		token:       token,
	}
}

func (s *Server) UnaryAuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if s.token == "" {
		return handler(ctx, req)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "missing metadata")
	}
	tokens := md["x-aegis-token"]
	if len(tokens) == 0 || tokens[0] != s.token {
		return nil, grpc.Errorf(codes.Unauthenticated, "invalid token")
	}
	return handler(ctx, req)
}

func (s *Server) StreamAuthInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if s.token == "" {
		return handler(srv, ss)
	}
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		return grpc.Errorf(codes.Unauthenticated, "missing metadata")
	}
	tokens := md["x-aegis-token"]
	if len(tokens) == 0 || tokens[0] != s.token {
		return grpc.Errorf(codes.Unauthenticated, "invalid token")
	}
	return handler(srv, ss)
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

	if len(events) > 5000 {
		events = events[:5000]
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
