package security

import "testing"

func TestVerifyPasswordWithBcryptHash(t *testing.T) {
	hash := HashPassword("Admin123!")
	if hash == legacySHA256("Admin123!") {
		t.Fatal("HashPassword returned legacy SHA-256 hash")
	}
	if !VerifyPassword("Admin123!", hash) {
		t.Fatal("bcrypt password did not verify")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("wrong password verified")
	}
	if NeedsPasswordRehash(hash) {
		t.Fatal("fresh bcrypt hash should not need rehash")
	}
}

func TestVerifyPasswordWithLegacySHA256Hash(t *testing.T) {
	hash := legacySHA256("Admin123!")
	if !VerifyPassword("Admin123!", hash) {
		t.Fatal("legacy SHA-256 password did not verify")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("wrong password verified against legacy SHA-256 hash")
	}
	if !NeedsPasswordRehash(hash) {
		t.Fatal("legacy SHA-256 hash should need rehash")
	}
}

func TestEncryptDecryptSecret(t *testing.T) {
	master := "super-secret-key-at-least-32-chars-long"
	plain := "my-step-ca-provisioner-password-123!"

	enc, err := EncryptSecret(plain, master)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}
	if enc == plain {
		t.Fatal("Ciphertext equals plaintext")
	}

	dec, err := DecryptSecret(enc, master)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}
	if dec != plain {
		t.Fatalf("expected decrypted %q, got %q", plain, dec)
	}

	// Wrong key fails
	if _, err := DecryptSecret(enc, "wrong-master-key-wrong-wrong-wrong"); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}

	// Empty string round-trip
	emptyDec, err := DecryptSecret("", master)
	if err != nil || emptyDec != "" {
		t.Fatalf("expected empty round-trip, got %q (err=%v)", emptyDec, err)
	}
}
