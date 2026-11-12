package editor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/editor"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// TestEditRoundTrip checks that an edit decrypts, edits and re-encrypts,
// and that the values survive.
func TestEditRoundTrip(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "group.sops.yaml")

	ed := editor.Editor{Command: scriptEditor(t, "TOKEN: edited\n")}
	result, err := ed.Edit(context.Background(), path, path, editor.Options{
		Format:     payload.NewSOPS(),
		Recipients: []string{recipient},
		Identities: []payload.Identity{identity},
		Template:   editor.DefaultTemplate,
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if !result.Created {
		t.Error("the group should be reported as created")
	}

	decrypted, err := payload.NewSOPS().Decrypt(context.Background(), mustRead(t, path), []payload.Identity{identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted["TOKEN"] != "edited" {
		t.Errorf("TOKEN = %v, want edited", decrypted["TOKEN"])
	}
}

// TestEditKeepsTheOtherValues checks that editing one value keeps the
// others.
func TestEditKeepsTheOtherValues(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "group.sops.yaml")

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), payload.Document{
		"KEEP": "this",
		"EDIT": "that",
	}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ed := editor.Editor{Command: scriptSetting(t, "EDIT", "changed")}
	if _, err := ed.Edit(context.Background(), path, path, editor.Options{
		Format:     sops,
		Recipients: []string{recipient},
		Identities: []payload.Identity{identity},
		Template:   editor.DefaultTemplate,
	}); err != nil {
		t.Fatalf("edit: %v", err)
	}

	decrypted, err := sops.Decrypt(context.Background(), mustRead(t, path), []payload.Identity{identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted["KEEP"] != "this" {
		t.Errorf("KEEP = %v, want this", decrypted["KEEP"])
	}
	if decrypted["EDIT"] != "changed" {
		t.Errorf("EDIT = %v, want changed", decrypted["EDIT"])
	}
}

// TestEditRefusesWhenItCannotDecrypt checks that the payload is not
// overwritten when the machine is not a recipient.
func TestEditRefusesWhenItCannotDecrypt(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)
	other, err := payload.NewAgeIdentity(otherPrivateKey)
	if err != nil {
		t.Fatalf("parsing the second identity: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "group.sops.yaml")

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ed := editor.Editor{Command: scriptEditor(t, "TOKEN: overwritten\n")}
	if _, err := ed.Edit(context.Background(), path, path, editor.Options{
		Format:     sops,
		Recipients: []string{recipient},
		Identities: []payload.Identity{other},
		Template:   editor.DefaultTemplate,
	}); err == nil {
		t.Fatal("the edit should fail when the group cannot be decrypted")
	}

	// The payload must be untouched.
	if string(mustRead(t, path)) != string(raw) {
		t.Error("the payload should not have been touched")
	}
}

// TestEditKeepsTheShapeWhenForced checks that a forced edit of a payload
// that cannot be decrypted keeps the key names.
func TestEditKeepsTheShapeWhenForced(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)
	other, err := payload.NewAgeIdentity(otherPrivateKey)
	if err != nil {
		t.Fatalf("parsing the second identity: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "group.sops.yaml")

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ed := editor.Editor{Command: scriptEditor(t, "TOKEN: overwritten\n")}
	if _, err := ed.Edit(context.Background(), path, path, editor.Options{
		Format:     sops,
		Recipients: []string{recipient},
		Identities: []payload.Identity{other},
		Force:      true,
		Template:   editor.DefaultTemplate,
	}); err != nil {
		t.Fatalf("edit: %v", err)
	}

	// The key name must still be there, so the shape of the group survives.
	shape, err := sops.Shape(mustRead(t, path))
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	if _, ok := shape["TOKEN"]; !ok {
		t.Errorf("the shape should keep the key name, got %v", shape)
	}
}

// TestEditFailsOnAMalformedDocument checks that a document that cannot be
// parsed is an error rather than an empty payload.
//
// Silently writing an empty payload would throw away the secrets.
func TestEditFailsOnAMalformedDocument(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "group.sops.yaml")

	ed := editor.Editor{Command: scriptEditor(t, "TOKEN: one\nTOKEN: two\n")}
	if _, err := ed.Edit(context.Background(), path, path, editor.Options{
		Format:     payload.NewSOPS(),
		Recipients: []string{recipient},
		Identities: []payload.Identity{identity},
		Template:   editor.DefaultTemplate,
	}); err == nil {
		t.Fatal("a document with a duplicate key should be an error")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the payload should not have been written")
	}
}

// TestEditConvertsTheFormat checks that changing the format keeps the
// values and removes the old payload.
func TestEditConvertsTheFormat(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "group.sops.yaml")
	target := filepath.Join(dir, "group.yaml.age")

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ed := editor.Editor{Command: scriptEditor(t, "TOKEN: s3cret\n")}
	result, err := ed.Edit(context.Background(), source, target, editor.Options{
		Format:       payload.NewAge(),
		SourceFormat: sops,
		Recipients:   []string{recipient},
		Identities:   []payload.Identity{identity},
		Template:     editor.DefaultTemplate,
	})
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if !result.Converted {
		t.Error("the edit should be reported as a conversion")
	}

	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Error("the old payload should have been removed")
	}

	decrypted, err := payload.NewAge().Decrypt(context.Background(), mustRead(t, target), []payload.Identity{identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted["TOKEN"] != "s3cret" {
		t.Errorf("TOKEN = %v, want s3cret", decrypted["TOKEN"])
	}
}

// scriptEditor writes a shell script that replaces the file it is given
// with the given content, and returns its path.
func scriptEditor(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "editor.sh")
	script := "#!/bin/sh\ncat > \"$1\" <<'EOF'\n" + content + "EOF\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// scriptSetting writes a shell script that sets one key in the file it is
// given, keeping the other keys, and returns its path.
//
// This is what an editor does: the user changes one value.
func scriptSetting(t *testing.T, key, value string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "editor.sh")
	script := "#!/bin/sh\n" +
		"if grep -q '^" + key + ":' \"$1\"; then\n" +
		"  sed -i 's|^" + key + ":.*|" + key + ": " + value + "|' \"$1\"\n" +
		"else\n" +
		"  printf '" + key + ": " + value + "\\n' >> \"$1\"\n" +
		"fi\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// mustRead reads a file, failing the test if it cannot.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// testIdentity returns an identity and its public key.
func testIdentity(t *testing.T) (*payload.AgeIdentity, string) {
	t.Helper()

	id, err := payload.NewAgeIdentity(testPrivateKey)
	if err != nil {
		t.Fatalf("parsing the test identity: %v", err)
	}
	return id, id.Recipient()
}

// testPrivateKey is a throwaway age identity. It protects nothing.
const testPrivateKey = "AGE-SECRET-KEY-1QQCSRQDV0L9Y9EDE54HXW7WDSZAPUVZRXG6KGA2JS76CG54LND3QXP38VW"

// otherPrivateKey is a second throwaway identity, used to check that a
// machine that is not a recipient cannot decrypt a payload.
const otherPrivateKey = "AGE-SECRET-KEY-196V8AC67DCZLQJXU5029RQNNKST5RCYDHHZ95LGPJES6GE84XQTQDAWA8R"
