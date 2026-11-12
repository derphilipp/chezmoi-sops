package payload_test

import (
	"context"
	"strings"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// TestAgeRoundTrip checks that a document survives an encrypt/decrypt cycle
// in the whole-file age format.
func TestAgeRoundTrip(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)

	doc := payload.Document{
		"TOKEN": "s3cret",
		"database": map[string]any{
			"host": "db.example.com",
			"port": 5432,
		},
	}

	age := payload.NewAge()
	raw, err := age.Encrypt(context.Background(), doc, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if strings.Contains(string(raw), "s3cret") {
		t.Errorf("the value should be encrypted, got:\n%s", raw)
	}

	decrypted, err := age.Decrypt(context.Background(), raw, []payload.Identity{identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted["TOKEN"] != "s3cret" {
		t.Errorf("TOKEN = %v, want s3cret", decrypted["TOKEN"])
	}
}

// TestAgeDecryptWithSeveralIdentities checks that the right identity is
// found even when another one is tried first.
//
// age consumes the stream while it looks for the matching stanza, so a
// reader that was used for a failed attempt cannot be reused.
func TestAgeDecryptWithSeveralIdentities(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)
	other, err := payload.NewAgeIdentity(otherPrivateKey)
	if err != nil {
		t.Fatalf("parsing the second identity: %v", err)
	}

	age := payload.NewAge()
	raw, err := age.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// The wrong identity comes first.
	decrypted, err := age.Decrypt(context.Background(), raw, []payload.Identity{other, identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted["TOKEN"] != "s3cret" {
		t.Errorf("TOKEN = %v, want s3cret", decrypted["TOKEN"])
	}
}

// TestAgeDecryptWithWrongIdentity checks that a machine that is not a
// recipient gets an error rather than wrong data.
func TestAgeDecryptWithWrongIdentity(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)
	other, err := payload.NewAgeIdentity(otherPrivateKey)
	if err != nil {
		t.Fatalf("parsing the second identity: %v", err)
	}

	age := payload.NewAge()
	raw, err := age.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := age.Decrypt(context.Background(), raw, []payload.Identity{other}); err == nil {
		t.Error("decrypting with the wrong identity should fail")
	}
}

// TestAgeHasNoShape checks that the age format does not pretend to have a
// shape: there is nothing readable in an encrypted blob.
func TestAgeHasNoShape(t *testing.T) {
	t.Parallel()

	age := payload.NewAge()
	if _, err := age.Shape([]byte("blob")); err == nil {
		t.Error("the age format should not have a shape")
	}
}
