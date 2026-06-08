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
)

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

func TestGenerateMITMCert(t *testing.T) {
	ca := createTestCA(t)

	cert, err := GenerateMITMCert("example.com", ca)
	if err != nil {
		t.Fatalf("GenerateMITMCert failed: %v", err)
	}

	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	// Parse the generated certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Verify common name
	if x509Cert.Subject.CommonName != "example.com" {
		t.Errorf("expected CN=example.com, got %s", x509Cert.Subject.CommonName)
	}

	// Verify DNS names
	if len(x509Cert.DNSNames) != 1 || x509Cert.DNSNames[0] != "example.com" {
		t.Errorf("expected DNSNames=[example.com], got %v", x509Cert.DNSNames)
	}

	// Verify key usage
	if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature")
	}
}
