package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Agent     AgentConfig     `yaml:"agent" mapstructure:"agent"`
	Telemetry TelemetryConfig `yaml:"telemetry" mapstructure:"telemetry"`
	Engines   EnginesConfig   `yaml:"engines" mapstructure:"engines"`
	Storage   StorageConfig   `yaml:"storage" mapstructure:"storage"`
	Response  ResponseConfig  `yaml:"response" mapstructure:"response"`
}

type AgentConfig struct {
	ID                       string `yaml:"id" mapstructure:"id"`
	LogLevel                 string `yaml:"log_level" mapstructure:"log_level"`
	IPCSocket                string `yaml:"ipc_socket" mapstructure:"ipc_socket"`
	IPCToken                 string `yaml:"ipc_token" mapstructure:"ipc_token"`
	HeartbeatIntervalSeconds int    `yaml:"heartbeat_interval_seconds" mapstructure:"heartbeat_interval_seconds"`
}

type TelemetryConfig struct {
	ProcessMonitoring  bool `yaml:"process_monitoring" mapstructure:"process_monitoring"`
	FileMonitoring     bool `yaml:"file_monitoring" mapstructure:"file_monitoring"`
	RegistryMonitoring bool `yaml:"registry_monitoring" mapstructure:"registry_monitoring"`
	NetworkMonitoring  bool `yaml:"network_monitoring" mapstructure:"network_monitoring"`
	USBMonitoring      bool `yaml:"usb_monitoring" mapstructure:"usb_monitoring"`
}

type EnginesConfig struct {
	HashReputation HashReputationConfig `yaml:"hash_reputation" mapstructure:"hash_reputation"`
	Yara           YaraConfig           `yaml:"yara" mapstructure:"yara"`
	Sigma          SigmaConfig          `yaml:"sigma" mapstructure:"sigma"`
	Heuristics     HeuristicsConfig     `yaml:"heuristics" mapstructure:"heuristics"`
}

type HashReputationConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	DBPath  string `yaml:"db_path" mapstructure:"db_path"`
}

type YaraConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	RulesDir string `yaml:"rules_dir" mapstructure:"rules_dir"`
}

type SigmaConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	RulesDir string `yaml:"rules_dir" mapstructure:"rules_dir"`
}

type HeuristicsConfig struct {
	EntropyThreshold float64 `yaml:"entropy_threshold" mapstructure:"entropy_threshold"`
}

type StorageConfig struct {
	Path          string `yaml:"path" mapstructure:"path"`
	RetentionDays int    `yaml:"retention_days" mapstructure:"retention_days"`
	MaxSizeMB     int    `yaml:"max_size_mb" mapstructure:"max_size_mb"`
}

type ResponseConfig struct {
	AutoMitigation bool           `yaml:"auto_mitigation" mapstructure:"auto_mitigation"`
	RiskThreshold  float64        `yaml:"risk_threshold" mapstructure:"risk_threshold"`
	Actions        []ActionConfig `yaml:"actions" mapstructure:"actions"`
	QuarantineKey  string         `yaml:"quarantine_key" mapstructure:"quarantine_key"`
}


type ActionConfig struct {
	Name    string `yaml:"name" mapstructure:"name"`
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
}

func LoadConfig(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var conf Config
	if err := v.Unmarshal(&conf); err != nil {
		return nil, err
	}

	return &conf, nil
}
