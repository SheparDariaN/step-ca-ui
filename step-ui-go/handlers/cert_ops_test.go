package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeIssuePolicy(t *testing.T) {
	t.Parallel()
	p, err := normalizeIssuePolicy("server", "720h", "EC:P-256", "app.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Duration != "720h" || p.Template != "server" || p.Purpose != purposeServer {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if _, err := normalizeIssuePolicy("wildcard", "8760h", "EC:P-256", "example.com"); err == nil {
		t.Fatal("wildcard without *. prefix must fail")
	}
	client, err := normalizeIssuePolicy("client", "8760h", "EC:P-256", "client-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Purpose != purposeClient {
		t.Fatalf("client template must request clientAuth: %+v", client)
	}
	internal, err := normalizeIssuePolicy("internal", "87600h", "EC:P-256", "svc.home.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if internal.Purpose != purposeInternal {
		t.Fatalf("internal template must request serverAuth+clientAuth: %+v", internal)
	}
}

func TestDurationExceedsMaxForIssue(t *testing.T) {
	t.Parallel()
	if !durationExceedsMax("87600h", "4380h") {
		t.Fatal("internal 10y must be rejected against web max 4380h")
	}
	if durationExceedsMax("720h", "4380h") {
		t.Fatal("720h must be allowed against 4380h")
	}
}

func TestStepCertificateArgsUsesPasswordFile(t *testing.T) {
	t.Parallel()
	args := stepCertificateArgs("https://step-ca:9443", "/root.crt", "web", "/tmp/web.pw", "720h", "EC:P-256", purposeClient, "app.local", "/c.crt", "/c.key")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-password") {
		t.Fatal("password must not appear in step argv")
	}
	if !containsPair(args, "--provisioner", "web") {
		t.Fatalf("expected --provisioner web in %v", args)
	}
	if !containsPair(args, "--provisioner-password-file", "/tmp/web.pw") {
		t.Fatalf("expected password file flag in %v", args)
	}
	if !containsPair(args, "--set", "x509Purpose=client") {
		t.Fatalf("expected x509Purpose template data in %v", args)
	}
}

func TestRevokeTokenArgsUsesPasswordFile(t *testing.T) {
	t.Parallel()
	args := revokeTokenArgs("https://step-ca:9443", "/root.crt", "admin", "/tmp/admin.pw", "1001")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-password") {
		t.Fatal("password must not appear in step argv")
	}
	if !containsPair(args, "--provisioner-password-file", "/tmp/admin.pw") {
		t.Fatalf("expected password file flag in %v", args)
	}
	if !contains(args, "--revoke") {
		t.Fatalf("expected --revoke in %v", args)
	}
	token := "header.payload.signature-value-long"
	revokeArgs := revokeWithTokenArgs("https://step-ca:9443", "/root.crt", token, "1001")
	if scrubToken("revoke failed "+token) != "revoke failed [token]" {
		t.Fatal("token must be scrubbed from step errors")
	}
	if !containsPair(revokeArgs, "--token", token) {
		t.Fatalf("expected token flag in %v", revokeArgs)
	}
	if contains(revokeArgs, "--cert") || contains(args, "--cert") {
		t.Fatal("revoke by serial must not pass the leaf certificate")
	}
}

func TestRevokeTokenArgsUsesRowProvisioner(t *testing.T) {
	t.Parallel()
	serial := "45354885331494592787502170066385744005"
	args := revokeTokenArgs("https://ca.example:443", "/root.crt", "corp", "/tmp/corp.pw", serial)
	if !containsPair(args, "--provisioner", "corp") {
		t.Fatalf("expected provisioner corp in %v", args)
	}
	if args[len(args)-1] != serial {
		t.Fatalf("expected serial as token subject, got %v", args)
	}
}

func TestAlreadyRevoked(t *testing.T) {
	t.Parallel()
	if alreadyRevoked(nil) {
		t.Fatal("nil error is not an already-revoked result")
	}
	if !alreadyRevoked(fmt.Errorf("The certificate has already been revoked.")) {
		t.Fatal("already been revoked response must be treated as success")
	}
	if !alreadyRevoked(fmt.Errorf("certificate already revoked")) {
		t.Fatal("already revoked response must be treated as success")
	}
	if alreadyRevoked(fmt.Errorf("remote error: tls: bad certificate")) {
		t.Fatal("tls error must stay a failure")
	}
}

func TestCertStorageDirSeparatesSameName(t *testing.T) {
	t.Parallel()
	first := certStorageDir("/certs", "dc01", "111")
	second := certStorageDir("/certs", "dc01", "222")
	if first == second {
		t.Fatal("same name with different serials must use different directories")
	}
	if first != filepath.Join("/certs", "dc01", "111") || second != filepath.Join("/certs", "dc01", "222") {
		t.Fatalf("unexpected paths: %s %s", first, second)
	}
}

func TestCommitIssuedFilesDoesNotOverwrite(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	tempDir := filepath.Join(root, "temp-issue")
	writeTestLeaf(t, tempDir, 111)
	certPath, keyPath, serial, err := commitIssuedFiles(root, "dc01", tempDir)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if serial != "111" {
		t.Fatalf("serial: %s", serial)
	}
	if certPath != filepath.Join(root, "dc01", "111", "certificate.crt") {
		t.Fatalf("cert path: %s", certPath)
	}
	if keyPath != filepath.Join(root, "dc01", "111", "private.key") {
		t.Fatalf("key path: %s", keyPath)
	}
	original, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	again := filepath.Join(root, "temp-again")
	writeTestLeaf(t, again, 111)
	if _, _, _, err := commitIssuedFiles(root, "dc01", again); err == nil {
		t.Fatal("existing serial directory must not be overwritten")
	}
	kept, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(original) {
		t.Fatal("existing certificate file was replaced")
	}
	other := filepath.Join(root, "temp-other")
	writeTestLeaf(t, other, 222)
	secondPath, _, secondSerial, err := commitIssuedFiles(root, "dc01", other)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if secondSerial != "222" || secondPath == certPath {
		t.Fatalf("second issue path: %s serial %s", secondPath, secondSerial)
	}
}

func writeTestLeaf(t *testing.T, dir string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "certificate.crt"), body, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte("test-key"), 0600); err != nil {
		t.Fatal(err)
	}
}

func contains(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func containsPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
