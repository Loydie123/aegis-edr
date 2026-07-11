package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	Version    = "unknown"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	fmt.Printf("Starting AEGIS EDR Daemon version %s (%s) built on %s...\n", Version, CommitHash, BuildTime)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Aegis daemon is running. Press Ctrl+C to terminate.")

	sig := <-sigs
	fmt.Printf("Received signal %s. Shutting down gracefully...\n", sig)
}
