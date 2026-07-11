package api

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type mockKiller struct{}

func (m *mockKiller) KillTree(pid int) error {
	return nil
}

type mockIsolator struct{}

func (m *mockIsolator) IsolateHost() error {
	return nil
}

func (m *mockIsolator) RestoreHost() error {
	return nil
}

type mockQuarantiner struct{}

func (m *mockQuarantiner) QuarantineFile(src, destDir string) error {
	return nil
}

func TestGetStatus(t *testing.T) {
	t.Parallel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	RegisterAegisServiceServer(s, NewServer(nil, &mockKiller{}, &mockIsolator{}, &mockQuarantiner{}))
	defer s.Stop()

	go func() {
		_ = s.Serve(lis)
	}()

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := NewAegisServiceClient(conn)
	res, err := client.GetStatus(context.Background(), &StatusRequest{})
	if err != nil {
		t.Fatalf("failed to query status: %v", err)
	}

	if res.Version != "1.0.0-Beta" {
		t.Errorf("expected version 1.0.0-Beta, got %s", res.Version)
	}
	if res.Status != "RUNNING" {
		t.Errorf("expected status RUNNING, got %s", res.Status)
	}
}

func TestTriggerResponse(t *testing.T) {
	t.Parallel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	RegisterAegisServiceServer(s, NewServer(nil, &mockKiller{}, &mockIsolator{}, &mockQuarantiner{}))
	defer s.Stop()

	go func() {
		_ = s.Serve(lis)
	}()

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := NewAegisServiceClient(conn)
	res, err := client.TriggerResponse(context.Background(), &ResponseRequest{
		Action:    "kill",
		TargetPid: 1234,
	})
	if err != nil {
		t.Fatalf("failed to trigger response: %v", err)
	}

	if !res.Success {
		t.Errorf("expected success to be true")
	}
	if res.ActionExecuted != "kill" {
		t.Errorf("expected ActionExecuted kill, got %s", res.ActionExecuted)
	}
}
