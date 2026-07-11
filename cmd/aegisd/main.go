package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"aegis-edr/pkg/api"
	"aegis-edr/pkg/config"
	"google.golang.org/grpc"
)

var (
	Version    = "unknown"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	fmt.Printf("Starting AEGIS EDR Daemon version %s (%s) built on %s...\n", Version, CommitHash, BuildTime)

	cfg, err := config.LoadConfig("configs/aegis.yaml")
	if err != nil {
		fmt.Printf("Warning: failed to load config: %v. Using defaults.\n", err)
		cfg = &config.Config{
			Agent: config.AgentConfig{
				IPCSocket: "/tmp/aegis.sock",
			},
		}
	}

	ipcPath := cfg.Agent.IPCSocket
	_ = os.Remove(ipcPath)

	listener, err := net.Listen("unix", ipcPath)
	if err != nil {
		fmt.Printf("Error: failed to listen on socket %s: %v\n", ipcPath, err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	api.RegisterAegisServiceServer(grpcServer, api.NewServer())

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	fmt.Printf("Aegis daemon is listening on UDS: %s\n", ipcPath)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs
	fmt.Printf("Received signal %s. Shutting down gracefully...\n", sig)

	grpcServer.GracefulStop()
	_ = os.Remove(ipcPath)
}
