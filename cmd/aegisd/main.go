package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aegis-edr/internal/config"
	"aegis-edr/internal/logger"
	"aegis-edr/internal/response/network"
	"aegis-edr/internal/response/process"
	"aegis-edr/internal/response/quarantine"
	"aegis-edr/internal/storage"
	"aegis-edr/pkg/api"
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
		"version", Version,
		"commit", CommitHash,
		"build_time", BuildTime,
	)

	store, err := storage.NewStorage("telemetry.db")
	if err != nil {
		logger.Log.Error("failed to initialize storage engine", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	ipcPath := cfg.Agent.IPCSocket
	_ = os.Remove(ipcPath)

	listener, err := net.Listen("unix", ipcPath)
	if err != nil {
		logger.Log.Error("failed to listen on UDS socket", "path", ipcPath, "error", err)
		os.Exit(1)
	}
	_ = os.Chmod(ipcPath, 0600)

	killer := process.NewProcessTreeKiller()
	isolator := network.NewNetworkIsolator()
	key := []byte(cfg.Response.QuarantineKey)
	if len(key) != 32 {
		logger.Log.Warn("Invalid quarantine key length. Using default fallback key.")
		key = []byte("12345678901234567890123456789012")
	}
	quarantiner := quarantine.NewQuarantiner(key)

	grpcServer := grpc.NewServer()
	api.RegisterAegisServiceServer(grpcServer, api.NewServer(store, killer, isolator, quarantiner))

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			logger.Log.Error("gRPC server serve failure", "error", err)
		}
	}()

	logger.Log.Info("Aegis daemon is listening on UDS socket", "path", ipcPath)

	pruneCtx, cancelPrune := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			cutoff := time.Now().Add(-7 * 24 * time.Hour)
			if err := store.PruneOldTelemetry(pruneCtx, cutoff); err != nil {
				logger.Log.Error("failed to prune old telemetry", "error", err)
			} else {
				logger.Log.Info("completed periodic telemetry pruning")
			}
			select {
			case <-ticker.C:
			case <-pruneCtx.Done():
				return
			}
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs
	logger.Log.Info("Received shutdown signal", "signal", sig.String())

	cancelPrune()
	grpcServer.GracefulStop()
	_ = os.Remove(ipcPath)
	logger.Log.Info("Aegis daemon stopped gracefully")
}
