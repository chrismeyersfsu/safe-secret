package proxy

import (
	"crypto/x509"
	"testing"
)

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
