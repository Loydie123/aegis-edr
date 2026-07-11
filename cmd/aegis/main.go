package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"aegis-edr/internal/config"
	"aegis-edr/pkg/api"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "modernc.org/sqlite"
)

var (
	Version    = "unknown"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type alertLog struct {
	RuleName    string
	Category    string
	TriggeredAt string
	Description string
}

type statusModel struct {
	client       api.AegisServiceClient
	conn         *grpc.ClientConn
	status       *api.StatusResponse
	err          error
	procCount    int
	fileCount    int
	netCount     int
	recentAlerts []alertLog
}

func (m statusModel) Init() tea.Cmd {
	return tick()
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
			return m, tea.Quit
		}
	case tickMsg:
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		res, err := m.client.GetStatus(ctx, &api.StatusRequest{})
		cancel()
		if err != nil {
			m.err = err
		} else {
			m.status = res
			m.err = nil

			db, dbErr := sql.Open("sqlite", "telemetry.db")
			if dbErr == nil {
				_ = db.QueryRow("SELECT COUNT(*) FROM processes").Scan(&m.procCount)
				_ = db.QueryRow("SELECT COUNT(*) FROM file_modifications").Scan(&m.fileCount)
				_ = db.QueryRow("SELECT COUNT(*) FROM network_connections").Scan(&m.netCount)

				rows, queryErr := db.Query("SELECT rule_name, category, triggered_at, description FROM alert_logs ORDER BY triggered_at DESC LIMIT 3")
				if queryErr == nil {
					var list []alertLog
					for rows.Next() {
						var item alertLog
						_ = rows.Scan(&item.RuleName, &item.Category, &item.TriggeredAt, &item.Description)
						list = append(list, item)
					}
					rows.Close()
					m.recentAlerts = list
				}
				db.Close()
			}
		}
		return m, tick()
	}
	return m, nil
}

func (m statusModel) View() string {
	var titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00ffd7")).
		Border(lipgloss.RoundedBorder()).
		Padding(0, 2).
		MarginBottom(1)

	var headerStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#ff007f")).
		MarginTop(1).
		MarginBottom(1)

	var labelStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#a3a3a3")).
		Width(20)

	var valueStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00ff00"))

	var errorStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#ff0000"))

	var footerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#525252")).
		MarginTop(1)

	s := titleStyle.Render("🛡️ AEGIS EDR LIVE MONITOR DASHBOARD") + "\n"

	if m.err != nil {
		s += errorStyle.Render(fmt.Sprintf("CONNECTION ERROR: %v\n", m.err))
	} else if m.status != nil {
		state := "RUNNING"
		if m.status.Status != "" {
			state = m.status.Status
		}

		cpuPercent := m.status.CpuUsage
		barLength := 10
		filledLength := int((cpuPercent / 100.0) * float64(barLength))
		if filledLength < 1 && cpuPercent > 0 {
			filledLength = 1
		}
		bar := ""
		for i := 0; i < barLength; i++ {
			if i < filledLength {
				bar += "█"
			} else {
				bar += "░"
			}
		}

		s += fmt.Sprintf("%s: %s\n", labelStyle.Render("Daemon State"), valueStyle.Render(state))
		s += fmt.Sprintf("%s: %s\n", labelStyle.Render("Agent Version"), valueStyle.Foreground(lipgloss.Color("#ffd700")).Render(m.status.Version))
		s += fmt.Sprintf("%s: [%s] %s\n", labelStyle.Render("CPU Utilization"), bar, valueStyle.Foreground(lipgloss.Color("#00e5ff")).Render(fmt.Sprintf("%.1f%%", cpuPercent)))
		s += fmt.Sprintf("%s: %s\n", labelStyle.Render("Memory Footprint"), valueStyle.Foreground(lipgloss.Color("#d700ff")).Render(fmt.Sprintf("%.1f MB", m.status.RamUsage)))

		s += headerStyle.Render("📊 TELEMETRY INGESTION METRICS") + "\n"
		s += fmt.Sprintf("%s: %d\n", labelStyle.Render("Total Processes"), m.procCount)
		s += fmt.Sprintf("%s: %d\n", labelStyle.Render("File Modifications"), m.fileCount)
		s += fmt.Sprintf("%s: %d\n", labelStyle.Render("Network Connections"), m.netCount)

		s += headerStyle.Render("🚨 RECENT SECURITY ALERTS (LIMIT 3)") + "\n"
		if len(m.recentAlerts) == 0 {
			s += lipgloss.NewStyle().Foreground(lipgloss.Color("#525252")).Render("No critical alerts logged.") + "\n"
		} else {
			for _, alert := range m.recentAlerts {
				alertTitleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff0055"))
				s += fmt.Sprintf("[%s] %s [%s]\n", alert.TriggeredAt, alertTitleStyle.Render(alert.RuleName), alert.Category)
				s += fmt.Sprintf("  %s\n", alert.Description)
			}
		}
	} else {
		s += "Fetching initial telemetry data...\n"
	}

	s += footerStyle.Render("Press [q] or [Esc] to exit dashboard.") + "\n"
	return s
}

type healthModel struct {
	status string
	err    error
}

func (m healthModel) Init() tea.Cmd {
	return nil
}

func (m healthModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
			return m, tea.Quit
		}
	}
	return m, tea.Quit
}

func (m healthModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("Health Check: FAILED (%v)\n", m.err)
	}
	return fmt.Sprintf("Health Check: OK (%s)\n", m.status)
}

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

			p := tea.NewProgram(statusModel{
				client: client,
				conn:   conn,
			})
			if _, errRun := p.Run(); errRun != nil {
				fmt.Printf("Error: status dashboard execution failed: %v\n", errRun)
				os.Exit(1)
			}
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
			var status string
			if err == nil {
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				res, errStatus := client.GetStatus(ctx, &api.StatusRequest{})
				if errStatus == nil {
					status = fmt.Sprintf("Daemon state: %s, version: %s", res.Status, res.Version)
				} else {
					err = errStatus
				}
			}

			p := tea.NewProgram(healthModel{status: status, err: err})
			if _, errRun := p.Run(); errRun != nil {
				fmt.Printf("Error: bubbletea health program failed: %v\n", errRun)
				os.Exit(1)
			}
		},
	}

	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Display active agent configuration properties",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.LoadConfig("configs/aegis.yaml")
			if err != nil {
				fmt.Printf("Error: failed to load configuration: %v\n", err)
				os.Exit(1)
			}

			var titleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#00ffd7")).
				MarginBottom(1)

			var labelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ffffff")).
				Width(25)

			var valueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ffd700"))

			fmt.Println(titleStyle.Render("AEGIS CONFIGURATION VALUES"))
			fmt.Println("=======================================")
			fmt.Printf("%s: %s\n", labelStyle.Render("Agent ID"), valueStyle.Render(cfg.Agent.ID))
			fmt.Printf("%s: %s\n", labelStyle.Render("Log Level"), valueStyle.Render(cfg.Agent.LogLevel))
			fmt.Printf("%s: %s\n", labelStyle.Render("IPC Socket Path"), valueStyle.Render(cfg.Agent.IPCSocket))
			fmt.Printf("%s: %s\n", labelStyle.Render("Heartbeat Interval"), valueStyle.Render(fmt.Sprintf("%d seconds", cfg.Agent.HeartbeatIntervalSeconds)))
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

	rootCmd.AddCommand(statusCmd, versionCmd, healthCmd, configCmd, responseCmd, forensicsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
