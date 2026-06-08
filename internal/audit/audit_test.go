package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestSecretInjected(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := &Logger{logger: slog.New(handler)}

	logger.SecretInjected("req-123", "DB_PASSWORD", "__SAFE_SECRET__NAME__DB_PASSWORD", "db.example.com", "/api/data", "POST")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["event"] != "secret_injected" {
		t.Errorf("expected event=secret_injected, got %v", entry["event"])
	}
	if entry["req_id"] != "req-123" {
		t.Errorf("expected req_id=req-123, got %v", entry["req_id"])
	}
	if entry["lookup"] != "DB_PASSWORD" {
		t.Errorf("expected lookup=DB_PASSWORD, got %v", entry["lookup"])
	}
}

func TestSecretNotFound(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := &Logger{logger: slog.New(handler)}

	logger.SecretNotFound("req-456", "API_KEY", "__SAFE_SECRET__NAME__API_KEY", "api.example.com", "/v1/users", "GET")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["event"] != "secret_not_found" {
		t.Errorf("expected event=secret_not_found, got %v", entry["event"])
	}
	if entry["dst_host"] != "api.example.com" {
		t.Errorf("expected dst_host=api.example.com, got %v", entry["dst_host"])
	}
}

func TestHostBlocked(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := &Logger{logger: slog.New(handler)}

	logger.HostBlocked("req-789", "TOKEN", "__SAFE_SECRET__ID__abc-123", "blocked.example.com", "/endpoint", "PUT")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["event"] != "host_blocked" {
		t.Errorf("expected event=host_blocked, got %v", entry["event"])
	}
	if entry["placeholder"] != "__SAFE_SECRET__ID__abc-123" {
		t.Errorf("expected placeholder=__SAFE_SECRET__ID__abc-123, got %v", entry["placeholder"])
	}
}

func TestScrubHit(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := &Logger{logger: slog.New(handler)}

	logger.ScrubHit("req-999", "scrub.example.com", "/response", "GET", 3)

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["event"] != "scrub_hit" {
		t.Errorf("expected event=scrub_hit, got %v", entry["event"])
	}
	if entry["scrubbed_count"] != float64(3) {
		t.Errorf("expected scrubbed_count=3, got %v", entry["scrubbed_count"])
	}
}

func TestScrubSkipped(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := &Logger{logger: slog.New(handler)}

	logger.ScrubSkipped("req-111", "skip.example.com", "content_type_mismatch")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["event"] != "scrub_skipped" {
		t.Errorf("expected event=scrub_skipped, got %v", entry["event"])
	}
	if entry["reason"] != "content_type_mismatch" {
		t.Errorf("expected reason=content_type_mismatch, got %v", entry["reason"])
	}
}

func TestTunnel(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger := &Logger{logger: slog.New(handler)}

	logger.Tunnel("tunnel.example.com")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["event"] != "tunnel" {
		t.Errorf("expected event=tunnel, got %v", entry["event"])
	}
	if entry["dst_host"] != "tunnel.example.com" {
		t.Errorf("expected dst_host=tunnel.example.com, got %v", entry["dst_host"])
	}
}
