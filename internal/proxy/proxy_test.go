package proxy

import (
	"crypto/tls"
	"testing"

	"github.com/chrismeyersfsu/safe-secret/internal/audit"
	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
)

func TestNewProxyServer(t *testing.T) {
	entries := []secrets.SecretEntry{
		{
			Name:         "TEST_SECRET",
			ID:           "123e4567-e89b-12d3-a456-426614174000",
			Value:        []byte("secret-value"),
			AllowedHosts: []string{"example.com"},
		},
	}

	store, err := secrets.NewInMemoryStore(entries)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Create a dummy CA cert (in real usage would use certgen)
	caCert := &tls.Certificate{}
	auditLog := audit.New()

	ps := NewProxyServer(store, caCert, auditLog, 100)

	if ps == nil {
		t.Fatal("expected non-nil ProxyServer")
	}

	if ps.store != store {
		t.Error("store not set correctly")
	}

	if ps.maxIdleConn != 100 {
		t.Errorf("expected maxIdleConn=100, got %d", ps.maxIdleConn)
	}

	// Check MITM hosts were populated
	if !ps.mitmHosts["example.com"] {
		t.Error("expected example.com in MITM hosts")
	}
}

func TestCertCache(t *testing.T) {
	caCert := &tls.Certificate{}
	cache := NewCertCache(caCert)

	if cache == nil {
		t.Fatal("expected non-nil CertCache")
	}

	if cache.ca != caCert {
		t.Error("CA cert not set correctly")
	}
}
