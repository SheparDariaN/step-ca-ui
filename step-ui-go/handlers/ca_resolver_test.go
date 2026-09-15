package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"step-ui/config"
)

func createTestCert(t *testing.T, isCA bool, cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}

	signerCert := tmpl
	signerKey := key
	if parent != nil && parentKey != nil {
		signerCert = parent
		signerKey = parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, parsed, key
}

func TestValidateUploadedCACert(t *testing.T) {
	// Valid CA cert
	validPEM, _, _ := createTestCert(t, true, "Test Root CA", nil, nil)
	cert, err := validateUploadedCACert(validPEM)
	if err != nil {
		t.Fatalf("expected valid CA cert, got error: %v", err)
	}
	if cert.Subject.CommonName != "Test Root CA" {
		t.Fatalf("expected CN 'Test Root CA', got %q", cert.Subject.CommonName)
	}

	// Non-CA cert must fail
	nonCAPEM, _, _ := createTestCert(t, false, "Leaf Cert", nil, nil)
	if _, err := validateUploadedCACert(nonCAPEM); err == nil {
		t.Fatal("expected error for non-CA cert")
	}

	// Invalid PEM garbage must fail
	if _, err := validateUploadedCACert([]byte("not a pem certificate")); err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestCAResolverBundledDefaults(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root_ca.crt")
	passPath := filepath.Join(dir, "provisioner_password")
	_ = os.WriteFile(rootPath, []byte("fake"), 0644)
	_ = os.WriteFile(passPath, []byte("pass"), 0600)

	cfg := &config.Config{
		CAMode:       "bundled",
		CAURL:        "https://step-ca:9443",
		RootCert:     rootPath,
		Provisioner:  "admin",
		PasswordFile: passPath,
		SecretKey:    "12345678901234567890123456789012",
	}

	h := &Handler{cfg: cfg}
	resolver, err := NewCAResolver(h)
	if err != nil {
		t.Fatalf("NewCAResolver failed: %v", err)
	}
	rt := resolver.Runtime()
	if rt.Mode != "bundled" {
		t.Fatalf("expected mode bundled, got %s", rt.Mode)
	}
	if rt.URL != "https://step-ca:9443" {
		t.Fatalf("expected URL https://step-ca:9443, got %s", rt.URL)
	}
	if !rt.Configured {
		t.Fatal("bundled mode should be marked configured by default")
	}
}

func TestCAResolverExternalUnconfigured(t *testing.T) {
	cfg := &config.Config{
		CAMode:       "external",
		CAURL:        "",
		RootCert:     "/non/existent/root.crt",
		Provisioner:  "",
		PasswordFile: "/non/existent/pw",
		SecretKey:    "12345678901234567890123456789012",
	}

	h := &Handler{cfg: cfg}
	resolver, err := NewCAResolver(h)
	if err != nil {
		t.Fatalf("NewCAResolver failed: %v", err)
	}
	rt := resolver.Runtime()
	if rt.Mode != "external" {
		t.Fatalf("expected mode external, got %s", rt.Mode)
	}
	if rt.Configured {
		t.Fatal("expected external with missing files/URL to be unconfigured")
	}
}
