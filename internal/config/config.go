package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Engines   EnginesConfig   `yaml:"engines"`
	Storage   StorageConfig   `yaml:"storage"`
	Response  ResponseConfig  `yaml:"response"`
}

type AgentConfig struct {
	ID                       string `yaml:"id"`
	LogLevel                 string `yaml:"log_level"`
	IPCSocket                string `yaml:"ipc_socket"`
	HeartbeatIntervalSeconds int    `yaml:"heartbeat_interval_seconds"`
}

type TelemetryConfig struct {
	ProcessMonitoring  bool `yaml:"process_monitoring"`
	FileMonitoring     bool `yaml:"file_monitoring"`
	RegistryMonitoring bool `yaml:"registry_monitoring"`
	NetworkMonitoring  bool `yaml:"network_monitoring"`
	USBMonitoring      bool `yaml:"usb_monitoring"`
}

type EnginesConfig struct {
	HashReputation HashReputationConfig `yaml:"hash_reputation"`
	Yara           YaraConfig           `yaml:"yara"`
	Sigma          SigmaConfig          `yaml:"sigma"`
	Heuristics     HeuristicsConfig     `yaml:"heuristics"`
}

type HashReputationConfig struct {
	Enabled bool   `yaml:"enabled"`
	DBPath  string `yaml:"db_path"`
}

type YaraConfig struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"`
}

type SigmaConfig struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"`
}

type HeuristicsConfig struct {
	EntropyThreshold float64 `yaml:"entropy_threshold"`
}

type StorageConfig struct {
	Path          string `yaml:"path"`
	RetentionDays int    `yaml:"retention_days"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
}

type ResponseConfig struct {
	AutoMitigation bool           `yaml:"auto_mitigation"`
	RiskThreshold  float64        `yaml:"risk_threshold"`
	Actions        []ActionConfig `yaml:"actions"`
}

type ActionConfig struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var conf Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&conf); err != nil {
		return nil, err
	}

	return &conf, nil
}
