package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Agent     AgentConfig     `mapstructure:"agent"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	Engines   EnginesConfig   `mapstructure:"engines"`
	Storage   StorageConfig   `mapstructure:"storage"`
	Response  ResponseConfig  `mapstructure:"response"`
}

type AgentConfig struct {
	ID                       string `mapstructure:"id"`
	LogLevel                 string `mapstructure:"log_level"`
	IPCSocket                string `mapstructure:"ipc_socket"`
	HeartbeatIntervalSeconds int    `mapstructure:"heartbeat_interval_seconds"`
}

type TelemetryConfig struct {
	ProcessMonitoring  bool `mapstructure:"process_monitoring"`
	FileMonitoring     bool `mapstructure:"file_monitoring"`
	RegistryMonitoring bool `mapstructure:"registry_monitoring"`
	NetworkMonitoring  bool `mapstructure:"network_monitoring"`
	USBMonitoring      bool `mapstructure:"usb_monitoring"`
}

type EnginesConfig struct {
	HashReputation HashReputationConfig `mapstructure:"hash_reputation"`
	Yara           YaraConfig           `mapstructure:"yara"`
	Sigma          SigmaConfig          `mapstructure:"sigma"`
	Heuristics     HeuristicsConfig     `mapstructure:"heuristics"`
}

type HashReputationConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	DBPath  string `mapstructure:"db_path"`
}

type YaraConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	RulesDir string `mapstructure:"rules_dir"`
}

type SigmaConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	RulesDir string `mapstructure:"rules_dir"`
}

type HeuristicsConfig struct {
	EntropyThreshold float64 `mapstructure:"entropy_threshold"`
}

type StorageConfig struct {
	Path          string `mapstructure:"path"`
	RetentionDays int    `mapstructure:"retention_days"`
	MaxSizeMB     int    `mapstructure:"max_size_mb"`
}

type ResponseConfig struct {
	AutoMitigation bool           `mapstructure:"auto_mitigation"`
	RiskThreshold  float64        `mapstructure:"risk_threshold"`
	Actions        []ActionConfig `mapstructure:"actions"`
}

type ActionConfig struct {
	Name    string `mapstructure:"name"`
	Enabled bool   `mapstructure:"enabled"`
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
