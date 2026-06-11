package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
)

type mockSecretStore struct {
	count int
	hosts []string
}

func (m *mockSecretStore) LookupByName(name string) (*secrets.SecretEntry, error) {
	return nil, secrets.ErrNotFound
}

func (m *mockSecretStore) LookupByID(id string) (*secrets.SecretEntry, error) {
	return nil, secrets.ErrNotFound
}

func (m *mockSecretStore) AllHosts() []string {
	return m.hosts
}

func (m *mockSecretStore) Count() int {
	return m.count
}

func TestHealthHandler_WithStore(t *testing.T) {
	store := &mockSecretStore{count: 3, hosts: []string{"host1.com", "host2.com"}}
	server := NewServer("127.0.0.1:8081", "/healthz", store, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var response Status
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %s", response.Status)
	}

	if response.CachedSecrets != 3 {
		t.Errorf("expected 3 cached secrets, got %d", response.CachedSecrets)
	}

	if len(response.MitmHosts) != 2 {
		t.Errorf("expected 2 mitm hosts, got %d", len(response.MitmHosts))
	}

	if response.UptimeSeconds <= 0 {
		t.Errorf("expected positive uptime, got %f", response.UptimeSeconds)
	}
}

func TestHealthHandler_NilStore(t *testing.T) {
	server := NewServer("127.0.0.1:8081", "/healthz", nil, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response Status
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %s", response.Status)
	}

	if response.CachedSecrets != 0 {
		t.Errorf("expected 0 cached secrets with nil store, got %d", response.CachedSecrets)
	}

	if response.MitmHosts != nil && len(response.MitmHosts) != 0 {
		t.Errorf("expected nil or empty mitm hosts with nil store, got %v", response.MitmHosts)
	}
}

func TestHealthHandler_EmptyStore(t *testing.T) {
	store := &mockSecretStore{count: 0, hosts: []string{}}
	server := NewServer("127.0.0.1:8081", "/healthz", store, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response Status
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.CachedSecrets != 0 {
		t.Errorf("expected 0 cached secrets, got %d", response.CachedSecrets)
	}

	if len(response.MitmHosts) != 0 {
		t.Errorf("expected 0 mitm hosts, got %d", len(response.MitmHosts))
	}
}

func TestNewServer_ConfigurableParams(t *testing.T) {
	store := &mockSecretStore{count: 1, hosts: []string{"host1.com"}}
	server := NewServer("0.0.0.0:9999", "/custom/health", store, nil)

	if server.listenAddr != "0.0.0.0:9999" {
		t.Errorf("expected listenAddr '0.0.0.0:9999', got %s", server.listenAddr)
	}

	if server.path != "/custom/health" {
		t.Errorf("expected path '/custom/health', got %s", server.path)
	}
}

func TestHealthHandler_JSONStructure(t *testing.T) {
	store := &mockSecretStore{count: 5, hosts: []string{"a.com", "b.com", "c.com"}}
	server := NewServer("127.0.0.1:8081", "/healthz", store, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	var response Status
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(response.MitmHosts) != 3 {
		t.Errorf("expected 3 mitm hosts, got %d: %v", len(response.MitmHosts), response.MitmHosts)
	}
}
