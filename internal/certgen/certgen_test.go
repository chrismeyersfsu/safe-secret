package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	if err := Generate(certPath, keyPath); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not created: %v", err)
	}

	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not created: %v", err)
	}

	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("cert permissions = %o, want 0644", certInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key permissions = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestGeneratedCertProperties(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	if err := Generate(certPath, keyPath); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}

	wantKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage != wantKeyUsage {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, wantKeyUsage)
	}

	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false, want true")
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not ECDSA")
	}

	if pubKey.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", pubKey.Curve.Params().Name)
	}

	if cert.Subject.CommonName != "safe-secret CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "safe-secret CA")
	}

	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "safe-secret" {
		t.Errorf("Organization = %v, want [safe-secret]", cert.Subject.Organization)
	}

	validityYears := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365
	if validityYears < 9.9 || validityYears > 10.1 {
		t.Errorf("validity period = %.1f years, want ~10", validityYears)
	}

	if time.Since(cert.NotBefore) > time.Minute {
		t.Errorf("NotBefore = %v, want recent", cert.NotBefore)
	}
}

func TestLoadCA(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	if err := Generate(certPath, keyPath); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	cert, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if cert == nil {
		t.Fatal("LoadCA returned nil certificate")
	}

	if len(cert.Certificate) == 0 {
		t.Error("loaded certificate has no certificate chain")
	}
}

func TestLoadCAMissingFiles(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name     string
		certPath string
		keyPath  string
	}{
		{
			name:     "missing cert",
			certPath: filepath.Join(tempDir, "missing.crt"),
			keyPath:  filepath.Join(tempDir, "ca.key"),
		},
		{
			name:     "missing key",
			certPath: filepath.Join(tempDir, "ca.crt"),
			keyPath:  filepath.Join(tempDir, "missing.key"),
		},
		{
			name:     "missing both",
			certPath: filepath.Join(tempDir, "missing.crt"),
			keyPath:  filepath.Join(tempDir, "missing.key"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "missing key" {
				if err := Generate(tt.certPath, filepath.Join(tempDir, "temp.key")); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}

			_, err := LoadCA(tt.certPath, tt.keyPath)
			if err == nil {
				t.Error("LoadCA succeeded with missing files, want error")
			}
		})
	}
}

func TestLoadOrGenerateCreatesWhenMissing(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	cert, err := LoadOrGenerate(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("LoadOrGenerate returned nil certificate")
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not created: %v", err)
	}

	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not created: %v", err)
	}
}

func TestLoadOrGenerateLoadsExisting(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	if err := Generate(certPath, keyPath); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	origCertData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read original cert: %v", err)
	}

	cert, err := LoadOrGenerate(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("LoadOrGenerate returned nil certificate")
	}

	newCertData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read new cert: %v", err)
	}

	if string(origCertData) != string(newCertData) {
		t.Error("LoadOrGenerate regenerated existing certificate")
	}
}
