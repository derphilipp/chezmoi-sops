package payload_test

import (
	"context"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// TestRecipients checks that the recipients of a sops payload can be read
// without the key.
//
// They are in the cleartext metadata of the document, which is what makes
// it possible to tell that a payload was not encrypted again after its
// group changed.
func TestRecipients(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)
	other, err := payload.NewAgeIdentity(otherPrivateKey)
	if err != nil {
		t.Fatalf("parsing the second identity: %v", err)
	}

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"},
		[]string{recipient, other.Recipient()})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	recipients, err := sops.Recipients(raw)
	if err != nil {
		t.Fatalf("recipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("the recipients = %v, want two", recipients)
	}

	found := map[string]bool{}
	for _, key := range recipients {
		found[key] = true
	}
	if !found[recipient] || !found[other.Recipient()] {
		t.Errorf("the recipients = %v, want both", recipients)
	}
}

// TestAgeHasNoRecipients checks that the whole-file age format cannot tell
// who a payload is encrypted for.
func TestAgeHasNoRecipients(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)

	age := payload.NewAge()
	raw, err := age.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	recipients, err := age.Recipients(raw)
	if err != nil {
		t.Fatalf("recipients: %v", err)
	}
	if len(recipients) != 0 {
		t.Errorf("the recipients = %v, want none", recipients)
	}
}
