package handlers

import (
	"bytes"
	"encoding/base32"
	"encoding/gob"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"step-ui/models"
)

func TestTOTPGenerationAndValidation(t *testing.T) {
	username := "admin"
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	secret := key.Secret()
	t.Logf("Generated secret: %s", secret)

	// Test decoding secretBytes
	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(cleanSecret, "="))
	if err != nil {
		secretBytes, err = base32.StdEncoding.DecodeString(cleanSecret)
	}
	if err != nil {
		t.Fatalf("Failed to decode base32 secret: %v", err)
	}

	// Regenerate key for QR (as Profile2FAQR does)
	qrKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
		Secret:      secretBytes,
	})
	if err != nil {
		t.Fatalf("Regenerating QR key failed: %v", err)
	}

	if qrKey.Secret() != secret {
		t.Fatalf("Secret mismatch: expected %q, got %q", secret, qrKey.Secret())
	}

	// Generate code from the QR key (simulating Authenticator app)
	now := time.Now()
	code, err := totp.GenerateCode(qrKey.Secret(), now)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Validate against the stored secret
	if !totp.Validate(code, secret) {
		t.Fatalf("totp.Validate failed for code %s with secret %s", code, secret)
	}
}

func TestFlashMsgGobEncoding(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	msg := models.FlashMsg{Type: "err", Text: "test error"}
	if err := enc.Encode(msg); err != nil {
		t.Fatalf("Failed to encode FlashMsg: %v", err)
	}
	dec := gob.NewDecoder(&buf)
	var decoded models.FlashMsg
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("Failed to decode FlashMsg: %v", err)
	}
	if decoded != msg {
		t.Fatalf("Decoded mismatch: got %+v, want %+v", decoded, msg)
	}
}
