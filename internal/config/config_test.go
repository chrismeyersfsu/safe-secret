package config

import (
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Proxy.Listen != "0.0.0.0:8080" {
		t.Errorf("expected proxy.listen to be 0.0.0.0:8080, got %s", cfg.Proxy.Listen)
	}
	if cfg.Proxy.MaxIdleConnsPerHost != 100 {
		t.Errorf("expected proxy.max_idle_conns_per_host to be 100, got %d", cfg.Proxy.MaxIdleConnsPerHost)
	}

	if cfg.TLS.CACertPath != "/etc/safe-secret/ca/rootCA.pem" {
		t.Errorf("expected tls.ca_cert_path to be /etc/safe-secret/ca/rootCA.pem, got %s", cfg.TLS.CACertPath)
	}
	if cfg.TLS.CertAlgorithm != "ecdsa-p256" {
		t.Errorf("expected tls.cert_algorithm to be ecdsa-p256, got %s", cfg.TLS.CertAlgorithm)
	}

	if cfg.Placeholders.Prefix != "__SAFE_SECRET__" {
		t.Errorf("expected placeholders.prefix to be __SAFE_SECRET__, got %s", cfg.Placeholders.Prefix)
	}

	if cfg.Bitwarden.CLIPath != "bw" {
		t.Errorf("expected bitwarden.cli_path to be bw, got %s", cfg.Bitwarden.CLIPath)
	}
	if cfg.Bitwarden.FolderName != "safe-secret" {
		t.Errorf("expected bitwarden.folder_name to be safe-secret, got %s", cfg.Bitwarden.FolderName)
	}

	if cfg.Keyring.SessionKeyDescription != "safe-secret:bw-session" {
		t.Errorf("expected keyring.session_key_description to be safe-secret:bw-session, got %s", cfg.Keyring.SessionKeyDescription)
	}

	if cfg.Pools.SecretBufferSize != 4096 {
		t.Errorf("expected pools.secret_buffer_size to be 4096, got %d", cfg.Pools.SecretBufferSize)
	}

	if len(cfg.Scrubbing.SkipContentTypes) != 4 {
		t.Errorf("expected 4 skip_content_types, got %d", len(cfg.Scrubbing.SkipContentTypes))
	}
	if len(cfg.Scrubbing.Encodings) != 4 {
		t.Errorf("expected 4 encodings, got %d", len(cfg.Scrubbing.Encodings))
	}

	if cfg.Renewal.SocketPath != "/run/safe-secret/renew.sock" {
		t.Errorf("expected renewal.socket_path to be /run/safe-secret/renew.sock, got %s", cfg.Renewal.SocketPath)
	}

	if cfg.Logging.Output != "journal" {
		t.Errorf("expected logging.output to be journal, got %s", cfg.Logging.Output)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected logging.level to be info, got %s", cfg.Logging.Level)
	}
	if cfg.Logging.File == nil {
		t.Fatal("expected logging.file to be set")
	}
	if cfg.Logging.File.Path != "/var/log/safe-secret/audit.jsonl" {
		t.Errorf("expected logging.file.path to be /var/log/safe-secret/audit.jsonl, got %s", cfg.Logging.File.Path)
	}

	if !cfg.Health.Enabled {
		t.Error("expected health.enabled to be true")
	}
	if cfg.Health.Listen != "127.0.0.1:8081" {
		t.Errorf("expected health.listen to be 127.0.0.1:8081, got %s", cfg.Health.Listen)
	}
	if cfg.Health.Path != "/healthz" {
		t.Errorf("expected health.path to be /healthz, got %s", cfg.Health.Path)
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := Defaults()
	if err := Validate(cfg); err != nil {
		t.Errorf("expected valid config to pass validation, got: %v", err)
	}
}

func TestValidate_BadProxyAddress(t *testing.T) {
	cfg := Defaults()
	cfg.Proxy.Listen = "not-a-valid-address"
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for invalid proxy.listen")
	}
}

func TestValidate_NonPositiveMaxIdleConns(t *testing.T) {
	cfg := Defaults()
	cfg.Proxy.MaxIdleConnsPerHost = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for non-positive max_idle_conns_per_host")
	}
}

func TestValidate_UnknownCertAlgorithm(t *testing.T) {
	cfg := Defaults()
	cfg.TLS.CertAlgorithm = "unknown-algo"
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for unknown cert_algorithm")
	}
}

func TestValidate_NonPositiveBitwardenTimeout(t *testing.T) {
	cfg := Defaults()
	cfg.Bitwarden.CLITimeout = -1
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for non-positive bitwarden.cli_timeout")
	}
}

func TestValidate_NonPositivePoolSize(t *testing.T) {
	cfg := Defaults()
	cfg.Pools.SecretBufferSize = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for non-positive pools.secret_buffer_size")
	}
}

func TestValidate_HealthNotLocalhost(t *testing.T) {
	cfg := Defaults()
	cfg.Health.Listen = "0.0.0.0:8081"
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for non-localhost health.listen")
	}
}

func TestValidate_BadHealthAddress(t *testing.T) {
	cfg := Defaults()
	cfg.Health.Listen = "invalid"
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for invalid health.listen address")
	}
}

func TestValidate_NonPositiveLogFileMaxSize(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.File.MaxSizeMB = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for non-positive logging.file.max_size_mb")
	}
}

func TestValidate_NegativeMaxBackups(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.File.MaxBackups = -1
	if err := Validate(cfg); err == nil {
		t.Error("expected validation to fail for negative logging.file.max_backups")
	}
}
