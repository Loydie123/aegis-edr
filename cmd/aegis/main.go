package main

import (
	"context"
	"fmt"
	"io"
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

func getGRPCClient() (api.AegisServiceClient, *grpc.ClientConn, error) {
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
		return nil, nil, err
	}

	return api.NewAegisServiceClient(conn), conn, nil
}

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
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon socket: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

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

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the AEGIS client and build version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("AEGIS EDR Client Version: %s\n", Version)
			fmt.Printf("Commit Hash             : %s\n", CommitHash)
			fmt.Printf("Build Time              : %s\n", BuildTime)
		},
	}

	var healthCmd = &cobra.Command{
		Use:   "health",
		Short: "Perform connection and dependency health checks",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Health Check: FAILED (Cannot connect to daemon socket: %v)\n", err)
				os.Exit(1)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := client.GetStatus(ctx, &api.StatusRequest{})
			if err != nil {
				fmt.Printf("Health Check: FAILED (gRPC call failed: %v)\n", err)
				os.Exit(1)
			}

			fmt.Printf("Health Check: OK (Daemon state: %s, version: %s)\n", res.Status, res.Version)
		},
	}

	var responseCmd = &cobra.Command{
		Use:   "response",
		Short: "Execute active containment responses",
	}

	var killPid int
	var killCmd = &cobra.Command{
		Use:   "kill",
		Short: "Terminate a process and all spawned descendants",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			res, err := client.TriggerResponse(ctx, &api.ResponseRequest{
				Action:    "kill",
				TargetPid: int32(killPid),
			})
			if err != nil {
				fmt.Printf("Error: action execution failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Success: %s\n", res.Message)
		},
	}
	killCmd.Flags().IntVar(&killPid, "pid", 0, "Target process PID")
	_ = killCmd.MarkFlagRequired("pid")

	var isolateCmd = &cobra.Command{
		Use:   "isolate",
		Short: "Isolate the host network interfaces from network outbound",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			res, err := client.TriggerResponse(ctx, &api.ResponseRequest{
				Action: "isolate",
			})
			if err != nil {
				fmt.Printf("Error: isolation execution failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Success: %s\n", res.Message)
		},
	}

	var restoreCmd = &cobra.Command{
		Use:   "restore",
		Short: "Restore host network isolation filters",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			res, err := client.TriggerResponse(ctx, &api.ResponseRequest{
				Action: "restore",
			})
			if err != nil {
				fmt.Printf("Error: restore execution failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Success: %s\n", res.Message)
		},
	}

	var quarFile string
	var quarantineCmd = &cobra.Command{
		Use:   "quarantine",
		Short: "Encrypt and quarantine a target threat payload",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			res, err := client.TriggerResponse(ctx, &api.ResponseRequest{
				Action:     "quarantine",
				TargetFile: quarFile,
			})
			if err != nil {
				fmt.Printf("Error: quarantine execution failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Success: %s\n", res.Message)
		},
	}
	quarantineCmd.Flags().StringVar(&quarFile, "file", "", "Target file absolute path")
	_ = quarantineCmd.MarkFlagRequired("file")

	responseCmd.AddCommand(killCmd, isolateCmd, restoreCmd, quarantineCmd)

	var startOffsetMinutes int
	var forensicsCmd = &cobra.Command{
		Use:   "forensics",
		Short: "Query chronological incident timeline reports",
		Run: func(cmd *cobra.Command, args []string) {
			client, conn, err := getGRPCClient()
			if err != nil {
				fmt.Printf("Error: failed to connect to daemon: %v\n", err)
				os.Exit(4)
			}
			defer conn.Close()

			ctx := context.Background()
			end := time.Now().Unix()
			start := time.Now().Add(-time.Duration(startOffsetMinutes) * time.Minute).Unix()

			stream, err := client.GetTimeline(ctx, &api.TimelineRequest{
				StartTimeEpoch: start,
				EndTimeEpoch:   end,
			})
			if err != nil {
				fmt.Printf("Error: failed to query forensics timeline: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("CHRONOLOGICAL INCIDENT TIMELINE")
			fmt.Println("=======================================")
			for {
				ev, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					fmt.Printf("Error: stream broken: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("[%s] [%s] %s\n", ev.Timestamp, ev.Category, ev.Description)
			}
		},
	}
	forensicsCmd.Flags().IntVar(&startOffsetMinutes, "minutes", 60, "Timeline window start offset in minutes")

	rootCmd.AddCommand(statusCmd, versionCmd, healthCmd, responseCmd, forensicsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
