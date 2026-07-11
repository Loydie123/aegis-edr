package tests

import (
	"context"
	"net"
	"os"
	"testing"

	"aegis-edr/internal/storage"
	"aegis-edr/pkg/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type dummyKiller struct{}

func (d *dummyKiller) KillTree(pid int) error {
	return nil
}

type dummyIsolator struct{}

func (d *dummyIsolator) IsolateHost() error {
	return nil
}

func (d *dummyIsolator) RestoreHost() error {
	return nil
}

type dummyQuarantiner struct{}

func (d *dummyQuarantiner) QuarantineFile(src, dest string) error {
	return nil
}

func TestE2EPipeline(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "aegis_e2e_*.db")
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

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	api.RegisterAegisServiceServer(grpcServer, api.NewServer(store, &dummyKiller{}, &dummyIsolator{}, &dummyQuarantiner{}, ""))
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := api.NewAegisServiceClient(conn)
	status, err := client.GetStatus(context.Background(), &api.StatusRequest{})
	if err != nil {
		t.Fatalf("failed to query status: %v", err)
	}

	if status.Status != "RUNNING" {
		t.Errorf("expected status RUNNING, got %s", status.Status)
	}

	resp, err := client.TriggerResponse(context.Background(), &api.ResponseRequest{
		Action: "isolate",
	})
	if err != nil {
		t.Fatalf("failed to trigger response: %v", err)
	}

	if !resp.Success || resp.ActionExecuted != "isolate" {
		t.Errorf("expected isolate success, got %v", resp)
	}
}
