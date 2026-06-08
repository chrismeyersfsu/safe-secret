package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type ProxyConfig struct {
	Listen              string `mapstructure:"listen"`
	MaxIdleConnsPerHost int    `mapstructure:"max_idle_conns_per_host"`
}

type TLSConfig struct {
	CACertPath    string `mapstructure:"ca_cert_path"`
	CAKeyPath     string `mapstructure:"ca_key_path"`
	CertAlgorithm string `mapstructure:"cert_algorithm"`
}

type PlaceholdersConfig struct {
	Prefix string `mapstructure:"prefix"`
}

type BitwardenConfig struct {
	CLIPath           string `mapstructure:"cli_path"`
	CLITimeout        int    `mapstructure:"cli_timeout"`
	SessionKeyTimeout int    `mapstructure:"session_key_timeout"`
	FolderName        string `mapstructure:"folder_name"`
	RefreshInterval   int    `mapstructure:"refresh_interval"`
}

type KeyringConfig struct {
	SessionKeyDescription string `mapstructure:"session_key_description"`
	CacheNamePrefix       string `mapstructure:"cache_name_prefix"`
	CacheIDPrefix         string `mapstructure:"cache_id_prefix"`
	CacheTTL              int    `mapstructure:"cache_ttl"`
}

type PoolsConfig struct {
	SecretBufferSize  int `mapstructure:"secret_buffer_size"`
	SecretBufferCount int `mapstructure:"secret_buffer_count"`
	ScrubBufferSize   int `mapstructure:"scrub_buffer_size"`
	ScrubBufferCount  int `mapstructure:"scrub_buffer_count"`
}

type ScrubbingConfig struct {
	SkipContentTypes    []string `mapstructure:"skip_content_types"`
	Encodings           []string `mapstructure:"encodings"`
	MaxResponseBuffer   string   `mapstructure:"max_response_buffer"`
}

type RenewalConfig struct {
	SocketPath string `mapstructure:"socket_path"`
	SocketMode string `mapstructure:"socket_mode"`
}

type FileConfig struct {
	Path        string `mapstructure:"path"`
	MaxSizeMB   int    `mapstructure:"max_size_mb"`
	MaxBackups  int    `mapstructure:"max_backups"`
	MaxAgeDays  int    `mapstructure:"max_age_days"`
}

type LoggingConfig struct {
	Output      string      `mapstructure:"output"`
	Level       string      `mapstructure:"level"`
	Format      string      `mapstructure:"format"`
	IncludePath bool        `mapstructure:"include_path"`
	File        *FileConfig `mapstructure:"file"`
}

type HealthConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
	Path    string `mapstructure:"path"`
}

type Config struct {
	Proxy        ProxyConfig        `mapstructure:"proxy"`
	TLS          TLSConfig          `mapstructure:"tls"`
	Placeholders PlaceholdersConfig `mapstructure:"placeholders"`
	Bitwarden    BitwardenConfig    `mapstructure:"bitwarden"`
	Keyring      KeyringConfig      `mapstructure:"keyring"`
	Pools        PoolsConfig        `mapstructure:"pools"`
	Scrubbing    ScrubbingConfig    `mapstructure:"scrubbing"`
	Renewal      RenewalConfig      `mapstructure:"renewal"`
	Logging      LoggingConfig      `mapstructure:"logging"`
	Health       HealthConfig       `mapstructure:"health"`
}

func Defaults() *Config {
	return &Config{
		Proxy: ProxyConfig{
			Listen:              "0.0.0.0:8080",
			MaxIdleConnsPerHost: 100,
		},
		TLS: TLSConfig{
			CACertPath:    "/etc/safe-secret/ca/rootCA.pem",
			CAKeyPath:     "/etc/safe-secret/ca/rootCA-key.pem",
			CertAlgorithm: "ecdsa-p256",
		},
		Placeholders: PlaceholdersConfig{
			Prefix: "__SAFE_SECRET__",
		},
		Bitwarden: BitwardenConfig{
			CLIPath:           "bw",
			CLITimeout:        60,
			SessionKeyTimeout: 28800,
			FolderName:        "safe-secret",
			RefreshInterval:   1800,
		},
		Keyring: KeyringConfig{
			SessionKeyDescription: "safe-secret:bw-session",
			CacheNamePrefix:       "safe-secret:cache:name:",
			CacheIDPrefix:         "safe-secret:cache:id:",
			CacheTTL:              43200,
		},
		Pools: PoolsConfig{
			SecretBufferSize:  4096,
			SecretBufferCount: 64,
			ScrubBufferSize:   65536,
			ScrubBufferCount:  16,
		},
		Scrubbing: ScrubbingConfig{
			SkipContentTypes:  []string{"application/octet-stream", "image/*", "video/*", "audio/*"},
			Encodings:         []string{"literal", "base64", "urlencode", "hex"},
			MaxResponseBuffer: "10MB",
		},
		Renewal: RenewalConfig{
			SocketPath: "/run/safe-secret/renew.sock",
			SocketMode: "0660",
		},
		Logging: LoggingConfig{
			Output:      "journal",
			Level:       "info",
			Format:      "jsonl",
			IncludePath: true,
			File: &FileConfig{
				Path:       "/var/log/safe-secret/audit.jsonl",
				MaxSizeMB:  100,
				MaxBackups: 3,
				MaxAgeDays: 30,
			},
		},
		Health: HealthConfig{
			Enabled: true,
			Listen:  "127.0.0.1:8081",
			Path:    "/healthz",
		},
	}
}

func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Set defaults
	cfg := Defaults()

	// Setup env var handling
	v.SetEnvPrefix("SAFE_SECRET")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// If a config file is provided, use it
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Check user config
		homeDir, err := os.UserHomeDir()
		if err == nil {
			userConfigPath := filepath.Join(homeDir, ".config", "safe-secret", "config.yaml")
			if _, err := os.Stat(userConfigPath); err == nil {
				v.SetConfigFile(userConfigPath)
			}
		}

		// Check system config if user config not found
		if v.ConfigFileUsed() == "" {
			systemConfigPath := "/etc/safe-secret/config.yaml"
			if _, err := os.Stat(systemConfigPath); err == nil {
				v.SetConfigFile(systemConfigPath)
			}
		}
	}

	// Read the config file if one was found
	if v.ConfigFileUsed() != "" {
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Unmarshal into our config struct
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}

func Validate(cfg *Config) error {
	// Validate proxy listen address
	if _, _, err := net.SplitHostPort(cfg.Proxy.Listen); err != nil {
		return fmt.Errorf("invalid proxy.listen address: %w", err)
	}

	if cfg.Proxy.MaxIdleConnsPerHost <= 0 {
		return fmt.Errorf("proxy.max_idle_conns_per_host must be positive")
	}

	// Validate cert algorithm
	validAlgos := map[string]bool{
		"ecdsa-p256": true,
		"ecdsa-p384": true,
		"rsa-2048":   true,
		"rsa-4096":   true,
	}
	if !validAlgos[cfg.TLS.CertAlgorithm] {
		return fmt.Errorf("unknown tls.cert_algorithm: %s (must be one of: ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096)", cfg.TLS.CertAlgorithm)
	}

	// Validate positive sizes
	if cfg.Bitwarden.CLITimeout <= 0 {
		return fmt.Errorf("bitwarden.cli_timeout must be positive")
	}
	if cfg.Bitwarden.SessionKeyTimeout <= 0 {
		return fmt.Errorf("bitwarden.session_key_timeout must be positive")
	}
	if cfg.Bitwarden.RefreshInterval <= 0 {
		return fmt.Errorf("bitwarden.refresh_interval must be positive")
	}

	if cfg.Keyring.CacheTTL <= 0 {
		return fmt.Errorf("keyring.cache_ttl must be positive")
	}

	if cfg.Pools.SecretBufferSize <= 0 {
		return fmt.Errorf("pools.secret_buffer_size must be positive")
	}
	if cfg.Pools.SecretBufferCount <= 0 {
		return fmt.Errorf("pools.secret_buffer_count must be positive")
	}
	if cfg.Pools.ScrubBufferSize <= 0 {
		return fmt.Errorf("pools.scrub_buffer_size must be positive")
	}
	if cfg.Pools.ScrubBufferCount <= 0 {
		return fmt.Errorf("pools.scrub_buffer_count must be positive")
	}

	// Validate health listen is localhost
	if cfg.Health.Enabled {
		host, _, err := net.SplitHostPort(cfg.Health.Listen)
		if err != nil {
			return fmt.Errorf("invalid health.listen address: %w", err)
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			return fmt.Errorf("health.listen must be localhost (127.0.0.1, localhost, or ::1), got: %s", host)
		}
	}

	if cfg.Logging.File != nil {
		if cfg.Logging.File.MaxSizeMB <= 0 {
			return fmt.Errorf("logging.file.max_size_mb must be positive")
		}
		if cfg.Logging.File.MaxBackups < 0 {
			return fmt.Errorf("logging.file.max_backups must be non-negative")
		}
		if cfg.Logging.File.MaxAgeDays <= 0 {
			return fmt.Errorf("logging.file.max_age_days must be positive")
		}
	}

	return nil
}
