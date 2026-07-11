package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"aegis-edr/pkg/api"
	"aegis-edr/internal/config"
	"aegis-edr/internal/logger"
	"aegis-edr/internal/storage"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var (
	Version    = "unknown"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	cfg, err := config.LoadConfig("configs/aegis.yaml")
	if err != nil {
		fmt.Printf("Warning: failed to load config: %v. Using defaults.\n", err)
		cfg = &config.Config{
			Agent: config.AgentConfig{
				LogLevel:  "info",
				IPCSocket: "/tmp/aegis.sock",
			},
		}
	}

	if err := logger.Init(cfg.Agent.LogLevel); err != nil {
		fmt.Printf("Error: failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.Log.Info("Starting AEGIS EDR Daemon",
		zap.String("version", Version),
		zap.String("commit", CommitHash),
		zap.String("build_time", BuildTime),
	)

	store, err := storage.NewStorage("telemetry.db")
	if err != nil {
		logger.Log.Fatal("failed to initialize storage engine", zap.Error(err))
	}
	defer store.Close()

	ipcPath := cfg.Agent.IPCSocket
	_ = os.Remove(ipcPath)

	listener, err := net.Listen("unix", ipcPath)
	if err != nil {
		logger.Log.Fatal("failed to listen on UDS socket", zap.String("path", ipcPath), zap.Error(err))
	}

	grpcServer := grpc.NewServer()
	api.RegisterAegisServiceServer(grpcServer, api.NewServer(store))

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			logger.Log.Error("gRPC server serve failure", zap.Error(err))
		}
	}()

	logger.Log.Info("Aegis daemon is listening on UDS socket", zap.String("path", ipcPath))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs
	logger.Log.Info("Received shutdown signal", zap.String("signal", sig.String()))

	grpcServer.GracefulStop()
	_ = os.Remove(ipcPath)
	logger.Log.Info("Aegis daemon stopped gracefully")
}
