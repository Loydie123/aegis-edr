package api

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"aegis-edr/internal/storage"
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

func TestGetTimeline(t *testing.T) {
	t.Parallel()

	tmpfile, err := os.CreateTemp("", "aegis_api_timeline_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	store, err := storage.NewStorage(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	t1 := time.Now().Truncate(time.Second)
	_, err = store.RawDBForTest().Exec("INSERT INTO processes (parent_id, binary_path, sha256, command_line, username, launched_at) VALUES (?, ?, ?, ?, ?, ?)",
		1, "/bin/ls", "hash1", "ls -la", "root", t1)
	if err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	RegisterAegisServiceServer(s, NewServer(store, &mockKiller{}, &mockIsolator{}, &mockQuarantiner{}))
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
	stream, err := client.GetTimeline(context.Background(), &TimelineRequest{
		StartTimeEpoch: t1.Add(-5 * time.Second).Unix(),
		EndTimeEpoch:   t1.Add(5 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}

	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("failed to receive stream event: %v", err)
	}

	if event.Category != "PROCESS" {
		t.Errorf("expected category PROCESS, got %s", event.Category)
	}
	if event.Description != "Process executed: /bin/ls (args: ls -la) by user root" {
		t.Errorf("unexpected description: %s", event.Description)
	}
}
