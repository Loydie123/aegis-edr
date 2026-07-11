package api

import (
	"context"
)

type Server struct {
	UnimplementedAegisServiceServer
}

func NewServer() *Server {
	return &Server{}
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
	return &ResponseResponse{
		Success:        true,
		Message:        "Containment action validated",
		ActionExecuted: req.Action,
	}, nil
}

func (s *Server) GetTimeline(req *TimelineRequest, stream AegisService_GetTimelineServer) error {
	return nil
}
