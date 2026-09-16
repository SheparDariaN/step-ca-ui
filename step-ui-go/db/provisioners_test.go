package db

import (
	"strings"
	"testing"
)

func TestValidateProvisionerRegistration(t *testing.T) {
	t.Parallel()
	if err := ValidateProvisionerRegistration("web", "JWK", "720h", "4380h", "admin"); err != nil {
		t.Fatalf("expected valid web provisioner, got %v", err)
	}
	if err := ValidateProvisionerRegistration("admin", "JWK", "8760h", "87600h", "admin"); err == nil {
		t.Fatal("expected error for system name admin")
	}
	if err := ValidateProvisionerRegistration("ops", "JWK", "8760h", "87600h", "ops"); err == nil {
		t.Fatal("expected error when name matches system provisioner")
	}
	if err := ValidateProvisionerRegistration("web", "ACME", "720h", "4380h", "admin"); err == nil {
		t.Fatal("expected error for non-JWK type")
	}
	if err := ValidateProvisionerRegistration("web", "JWK", "2160h", "4380h", "admin"); err == nil {
		t.Fatal("expected error for duration outside allowlist")
	}
	if err := ValidateProvisionerRegistration("web", "JWK", "87600h", "720h", "admin"); err == nil {
		t.Fatal("expected error when default exceeds max")
	}
	if err := ValidateProvisionerRegistration("../etc", "JWK", "720h", "4380h", "admin"); err == nil {
		t.Fatal("expected error for invalid name")
	}
}

func TestDurationExceedsMax(t *testing.T) {
	t.Parallel()
	if !DurationExceedsMax("87600h", "4380h") {
		t.Fatal("87600h must exceed 4380h")
	}
	if DurationExceedsMax("720h", "4380h") {
		t.Fatal("720h must not exceed 4380h")
	}
	if DurationExceedsMax("4380h", "4380h") {
		t.Fatal("equal durations must be allowed")
	}
	if !DurationExceedsMax("not-a-duration", "4380h") {
		t.Fatal("invalid requested duration must fail closed")
	}
}

func TestProvisionerNameValidation(t *testing.T) {
	t.Parallel()
	if err := ValidateProvisionerRegistration("web-01", "jwk", "720h", "4380h", "admin"); err != nil {
		t.Fatalf("hyphenated name should be valid: %v", err)
	}
	if err := ValidateProvisionerRegistration(strings.Repeat("a", 80), "JWK", "720h", "4380h", "admin"); err == nil {
		t.Fatal("overlong name must fail")
	}
}
