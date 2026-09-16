package handlers

import (
	"strings"
	"testing"
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

func containsPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
