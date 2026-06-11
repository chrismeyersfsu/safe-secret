package bitwarden

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseItems_ValidEntries(t *testing.T) {
	items := []BWItem{
		{
			ID:   "id-1",
			Name: "GITHUB_TOKEN",
			Login: &BWLogin{
				Password: "ghp_secret123",
				URIs: []BWURI{
					{URI: "https://api.github.com", Match: intPtr(0)},
				},
			},
		},
		{
			ID:   "id-2",
			Name: "GITLAB_TOKEN",
			Login: &BWLogin{
				Password: "glpat-secret456",
				URIs: []BWURI{
					{URI: "https://gitlab.com", Match: intPtr(1)},
				},
			},
		},
	}

	entries, err := ParseItems(items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Name != "GITHUB_TOKEN" {
		t.Errorf("expected name GITHUB_TOKEN, got %s", entries[0].Name)
	}
	if entries[0].ID != "id-1" {
		t.Errorf("expected id id-1, got %s", entries[0].ID)
	}
	if string(entries[0].Value) != "ghp_secret123" {
		t.Errorf("expected value ghp_secret123, got %s", entries[0].Value)
	}
}

func TestParseItems_SkipsNilLogin(t *testing.T) {
	items := []BWItem{
		{ID: "id-1", Name: "NO_LOGIN", Login: nil},
	}

	entries, err := ParseItems(items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseItems_SkipsEmptyPassword(t *testing.T) {
	items := []BWItem{
		{
			ID:    "id-1",
			Name:  "EMPTY_PASS",
			Login: &BWLogin{Password: "", URIs: []BWURI{{URI: "https://example.com"}}},
		},
	}

	entries, err := ParseItems(items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestExtractHosts_BaseDomainMatch(t *testing.T) {
	uris := []BWURI{
		{URI: "https://api.github.com", Match: intPtr(0)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "github.com" {
		t.Errorf("expected github.com, got %s", hosts[0])
	}
}

func TestExtractHosts_NilMatchDefaultsToBaseDomain(t *testing.T) {
	uris := []BWURI{
		{URI: "https://api.github.com", Match: nil},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "github.com" {
		t.Errorf("expected github.com, got %s", hosts[0])
	}
}

func TestExtractHosts_ExactMatch(t *testing.T) {
	uris := []BWURI{
		{URI: "https://api.github.com", Match: intPtr(1)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "api.github.com" {
		t.Errorf("expected api.github.com, got %s", hosts[0])
	}
}

func TestExtractHosts_StripsPort(t *testing.T) {
	uris := []BWURI{
		{URI: "https://api.example.com:8443/path", Match: intPtr(1)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", hosts[0])
	}
}

func TestExtractHosts_InvalidURI(t *testing.T) {
	uris := []BWURI{
		{URI: "not a valid uri ://", Match: intPtr(0)},
		{URI: "", Match: intPtr(0)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts for invalid URIs, got %d: %v", len(hosts), hosts)
	}
}

func TestExtractHosts_Deduplication(t *testing.T) {
	uris := []BWURI{
		{URI: "https://api.github.com", Match: intPtr(0)},
		{URI: "https://uploads.github.com", Match: intPtr(0)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 deduplicated host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "github.com" {
		t.Errorf("expected github.com, got %s", hosts[0])
	}
}

func TestExtractHosts_MultipleURIs(t *testing.T) {
	uris := []BWURI{
		{URI: "https://github.com", Match: intPtr(0)},
		{URI: "https://gitlab.com", Match: intPtr(1)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestExtractHosts_TwoLabelDomain(t *testing.T) {
	uris := []BWURI{
		{URI: "https://example.com", Match: intPtr(0)},
	}

	hosts := ExtractHosts(uris)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0] != "example.com" {
		t.Errorf("expected example.com, got %s", hosts[0])
	}
}

func TestBaseDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"api.github.com", "github.com"},
		{"github.com", "github.com"},
		{"sub.api.github.com", "github.com"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		got := baseDomain(tt.input)
		if got != tt.expected {
			t.Errorf("baseDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCheckSession_WithFakeBW(t *testing.T) {
	script := writeFakeBW(t, `#!/bin/bash
if [ "$1" = "status" ]; then
    echo '{"status":"unlocked","userEmail":"test@example.com"}'
    exit 0
fi
exit 1
`)

	client := NewClient(script, 5*time.Second, "safe-secret", "fake-session")
	err := client.CheckSession(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestCheckSession_Locked(t *testing.T) {
	script := writeFakeBW(t, `#!/bin/bash
if [ "$1" = "status" ]; then
    echo '{"status":"locked"}'
    exit 0
fi
exit 1
`)

	client := NewClient(script, 5*time.Second, "safe-secret", "fake-session")
	err := client.CheckSession(context.Background())
	if err == nil {
		t.Fatal("expected error for locked vault")
	}
	if !contains(err.Error(), "locked") {
		t.Errorf("expected error to mention locked, got: %v", err)
	}
}

func TestLoadSecrets_WithFakeBW(t *testing.T) {
	script := writeFakeBW(t, `#!/bin/bash
if [ "$1" = "list" ] && [ "$2" = "folders" ]; then
    echo '[{"id":"folder-123","name":"safe-secret"}]'
    exit 0
fi
if [ "$1" = "list" ] && [ "$2" = "items" ]; then
    echo '[{"id":"item-1","name":"API_KEY","folderId":"folder-123","login":{"password":"sk-secret","uris":[{"uri":"https://api.example.com","match":1}]}}]'
    exit 0
fi
exit 1
`)

	client := NewClient(script, 5*time.Second, "safe-secret", "fake-session")
	entries, err := client.LoadSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Name != "API_KEY" {
		t.Errorf("expected name API_KEY, got %s", entries[0].Name)
	}
	if string(entries[0].Value) != "sk-secret" {
		t.Errorf("expected value sk-secret, got %s", entries[0].Value)
	}
	if len(entries[0].AllowedHosts) != 1 || entries[0].AllowedHosts[0] != "api.example.com" {
		t.Errorf("expected allowed host api.example.com, got %v", entries[0].AllowedHosts)
	}
}

func TestLoadSecrets_FolderNotFound(t *testing.T) {
	script := writeFakeBW(t, `#!/bin/bash
if [ "$1" = "list" ] && [ "$2" = "folders" ]; then
    echo '[{"id":"folder-other","name":"other-folder"}]'
    exit 0
fi
exit 1
`)

	client := NewClient(script, 5*time.Second, "safe-secret", "fake-session")
	_, err := client.LoadSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error for missing folder")
	}
	if !contains(err.Error(), "not found") {
		t.Errorf("expected error to mention not found, got: %v", err)
	}
}

func TestRunBW_SessionInEnv(t *testing.T) {
	script := writeFakeBW(t, `#!/bin/bash
echo "$BW_SESSION"
`)

	client := NewClient(script, 5*time.Second, "safe-secret", "test-session-value")
	out, err := client.runBW(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := strings.TrimSpace(string(out))
	if got != "test-session-value" {
		t.Errorf("expected BW_SESSION=test-session-value in env, got %q", got)
	}
}

func writeFakeBW(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-bw")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("write fake bw: %v", err)
	}
	return path
}

func intPtr(v int) *int {
	return &v
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
