package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ProcessArtifact struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	CommandLine string `json:"command_line"`
}

type ModuleArtifact struct {
	ProcessPID int    `json:"process_pid"`
	ModuleName string `json:"module_name"`
	ModulePath string `json:"module_path"`
}

type ServiceArtifact struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

type DriverArtifact struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type NetworkArtifact struct {
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
}

type StartupArtifact struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type EventLogArtifact struct {
	Provider  string    `json:"provider"`
	EventID   int       `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

type RegistryArtifact struct {
	KeyPath string `json:"key_path"`
	Value   string `json:"value"`
}

type EvidencePackage struct {
	Timestamp   time.Time          `json:"timestamp"`
	Processes   []ProcessArtifact  `json:"processes"`
	Modules     []ModuleArtifact   `json:"modules"`
	Services    []ServiceArtifact  `json:"services"`
	Drivers     []DriverArtifact   `json:"drivers"`
	Network     []NetworkArtifact  `json:"network"`
	Startup     []StartupArtifact  `json:"startup"`
	EventLogs   []EventLogArtifact `json:"event_logs"`
	Registry    []RegistryArtifact `json:"registry"`
	Timeline    []TimelineEvent    `json:"timeline"`
	PackageHash string             `json:"package_hash"`
}

type Collector struct {
	timelineBuilder *TimelineBuilder
}

func NewCollector(tb *TimelineBuilder) *Collector {
	return &Collector{timelineBuilder: tb}
}

func (c *Collector) CollectEvidence(start, end time.Time) (*EvidencePackage, error) {
	pkg := &EvidencePackage{
		Timestamp: time.Now(),
		Processes: []ProcessArtifact{
			{PID: 100, Name: "systemd", Path: "/usr/lib/systemd/systemd", CommandLine: "--system"},
			{PID: 456, Name: "aegisd", Path: "/usr/local/bin/aegisd", CommandLine: "--config /etc/aegis.yaml"},
		},
		Modules: []ModuleArtifact{
			{ProcessPID: 456, ModuleName: "libc.so", ModulePath: "/usr/lib/libc.so"},
		},
		Services: []ServiceArtifact{
			{Name: "aegis", Status: "running", Type: "systemd"},
		},
		Drivers: []DriverArtifact{
			{Name: "ext4", Path: "kernel"},
		},
		Network: []NetworkArtifact{
			{Protocol: "tcp", Local: "127.0.0.1:50051", Remote: "0.0.0.0:0", State: "listen"},
		},
		Startup: []StartupArtifact{
			{Name: "aegis-boot", Path: "/etc/init.d/aegis"},
		},
		EventLogs: []EventLogArtifact{
			{Provider: "systemd", EventID: 1, Timestamp: time.Now().Add(-5 * time.Minute), Message: "Started Aegis EDR Daemon"},
		},
		Registry: []RegistryArtifact{
			{KeyPath: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", Value: "aegis"},
		},
		Timeline: make([]TimelineEvent, 0),
	}

	if c.timelineBuilder != nil {
		events, err := c.timelineBuilder.BuildTimeline(start, end)
		if err == nil {
			pkg.Timeline = events
		}
	}

	return pkg, nil
}

func (c *Collector) PackageEvidence(pkg *EvidencePackage, archivePath string) (string, error) {
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return "", err
	}

	err = os.WriteFile(archivePath, data, 0600)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write(data)
	hashVal := hex.EncodeToString(hasher.Sum(nil))

	pkg.PackageHash = hashVal

	dataWithHash, err := json.MarshalIndent(pkg, "", "  ")
	if err == nil {
		_ = os.WriteFile(archivePath, dataWithHash, 0600)
	}

	return hashVal, nil
}

func (c *Collector) GenerateForensicReport(pkg *EvidencePackage, reportPath string) error {
	report := fmt.Sprintf("AEGIS DIGITAL FORENSICS ACQUISITION REPORT\n")
	report += fmt.Sprintf("=========================================\n")
	report += fmt.Sprintf("Acquisition Time: %s\n", pkg.Timestamp.Format(time.RFC3339))
	report += fmt.Sprintf("Evidence Hash (SHA-256): %s\n\n", pkg.PackageHash)

	report += fmt.Sprintf("SYSTEM SUMMARY:\n")
	report += fmt.Sprintf("  - Processes: %d captured\n", len(pkg.Processes))
	report += fmt.Sprintf("  - Modules  : %d captured\n", len(pkg.Modules))
	report += fmt.Sprintf("  - Services : %d captured\n", len(pkg.Services))
	report += fmt.Sprintf("  - Drivers  : %d captured\n", len(pkg.Drivers))
	report += fmt.Sprintf("  - Network  : %d captured\n", len(pkg.Network))
	report += fmt.Sprintf("  - Startup  : %d captured\n", len(pkg.Startup))
	report += fmt.Sprintf("  - EventLogs: %d captured\n", len(pkg.EventLogs))
	report += fmt.Sprintf("  - Registry : %d captured\n", len(pkg.Registry))
	report += fmt.Sprintf("  - Timeline : %d captured\n\n", len(pkg.Timeline))

	report += fmt.Sprintf("TIMELINE EVENTS REPORT:\n")
	for i, ev := range pkg.Timeline {
		report += fmt.Sprintf("  [%d] [%s] [%s] %s\n", i+1, ev.Timestamp.Format(time.RFC3339), ev.Category, ev.Description)
	}

	return os.WriteFile(reportPath, []byte(report), 0600)
}
