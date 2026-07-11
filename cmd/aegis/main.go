package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"aegis-edr/pkg/api"
	"aegis-edr/pkg/config"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	Version    = "unknown"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "aegis",
		Short: "AEGIS Endpoint Detection and Response Client",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	var statusCmd = &cobra.Command{
		Use:   "status",
		Short: "View daemon health and configuration profiles",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.LoadConfig("configs/aegis.yaml")
			if err != nil {
				cfg = &config.Config{
					Agent: config.AgentConfig{
						IPCSocket: "/tmp/aegis.sock",
					},
				}
			}

			conn, err := grpc.Dial(
				cfg.Agent.IPCSocket,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
					return net.Dial("unix", addr)
				}),
			)
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon socket: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

			client := api.NewAegisServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := client.GetStatus(ctx, &api.StatusRequest{})
			if err != nil {
				fmt.Printf("Error: failed to query daemon status: %v\n", err)
				os.Exit(4)
			}

			fmt.Println("AEGIS AGENT STATUS")
			fmt.Println("=======================================")
			fmt.Printf("Daemon Status : %s\n", res.Status)
			fmt.Printf("Version       : %s\n", res.Version)
			fmt.Printf("CPU Usage     : %.1f%%\n", res.CpuUsage)
			fmt.Printf("RAM Footprint : %.1f MB\n", res.RamUsage)
		},
	}

	rootCmd.AddCommand(statusCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
