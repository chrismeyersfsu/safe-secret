package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

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
	// Create a test CA
	ca := createTestCA(t)
	cache := NewCertCache(ca)

	if cache == nil {
		t.Fatal("expected non-nil CertCache")
	}

	if cache.ca != ca {
		t.Error("CA cert not set correctly")
	}
}

func TestCertCache_Fetch(t *testing.T) {
	ca := createTestCA(t)
	cache := NewCertCache(ca)

	// Fetch cert for example.com
	cert1, err := cache.Fetch("example.com", nil)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if cert1 == nil {
		t.Fatal("expected non-nil cert")
	}

	// Fetch again - should return cached cert
	cert2, err := cache.Fetch("example.com", nil)
	if err != nil {
		t.Fatalf("second Fetch failed: %v", err)
	}

	// Should be same pointer (cached)
	if cert1 != cert2 {
		t.Error("expected cached cert to be returned")
	}

	// Different host should generate new cert
	cert3, err := cache.Fetch("other.com", nil)
	if err != nil {
		t.Fatalf("Fetch for different host failed: %v", err)
	}
	if cert3 == cert1 {
		t.Error("expected different cert for different host")
	}
}

func createTestCA(t *testing.T) *tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "test CA",
			Organization: []string{"test"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}
