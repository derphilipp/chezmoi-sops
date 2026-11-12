package payload_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// TestSOPSRoundTrip checks that a document survives an encrypt/decrypt cycle.
func TestSOPSRoundTrip(t *testing.T) {
	t.Parallel()

	identity, recipient := testIdentity(t)

	doc := payload.Document{
		"TOKEN": "s3cret",
		"database": map[string]any{
			"host": "db.example.com",
			"port": 5432,
		},
	}

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), doc, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if !strings.Contains(string(raw), "TOKEN:") {
		t.Errorf("the key names should stay readable, got:\n%s", raw)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Errorf("the value should be encrypted, got:\n%s", raw)
	}

	decrypted, err := sops.Decrypt(context.Background(), raw, []payload.Identity{identity})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if decrypted["TOKEN"] != "s3cret" {
		t.Errorf("TOKEN = %v, want s3cret", decrypted["TOKEN"])
	}
	nested, ok := decrypted["database"].(payload.Document)
	if !ok {
		t.Fatalf("database = %T, want a document", decrypted["database"])
	}
	if nested["host"] != "db.example.com" {
		t.Errorf("database.host = %v, want db.example.com", nested["host"])
	}
}

// TestSOPSShape checks that the shape of a document is readable without
// decrypting it.
func TestSOPSShape(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)

	doc := payload.Document{
		"TOKEN": "s3cret",
		"database": map[string]any{
			"host": "db.example.com",
		},
	}

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), doc, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	shape, err := sops.Shape(raw)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}

	if shape["TOKEN"] != "" {
		t.Errorf("TOKEN = %v, want an empty value", shape["TOKEN"])
	}
	if _, ok := shape["database"]; !ok {
		t.Errorf("the shape should keep the database key, got %v", shape)
	}
	if _, ok := shape["sops"]; ok {
		t.Errorf("the shape should not contain the sops metadata")
	}
}

// TestSOPSDecryptWithWrongIdentity checks that a machine that is not a
// recipient gets an error rather than wrong data.
func TestSOPSDecryptWithWrongIdentity(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)
	other, err := payload.NewAgeIdentity(otherPrivateKey)
	if err != nil {
		t.Fatalf("parsing the second test identity: %v", err)
	}

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), payload.Document{"TOKEN": "s3cret"}, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := sops.Decrypt(context.Background(), raw, []payload.Identity{other}); err == nil {
		t.Error("decrypting with the wrong identity should fail")
	}
}

// TestSOPSCompatibleWithCLI checks that the real sops binary can decrypt what
// the tool writes, and the other way round.
//
// This is the compatibility test that makes the pinned library safe: the
// sops binary is the oracle, not our own code.
func TestSOPSCompatibleWithCLI(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("the sops binary is not installed")
	}

	identity, recipient := testIdentity(t)
	dir := t.TempDir()

	// The sops binary looks for the identity in SOPS_AGE_KEY_FILE.
	keyFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(keyFile, []byte(testPrivateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "SOPS_AGE_KEY_FILE="+keyFile)

	// The tool writes, the sops binary reads.
	doc := payload.Document{"TOKEN": "s3cret", "NESTED": map[string]any{"KEY": "value"}}
	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), doc, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	toolPath := filepath.Join(dir, "tool.yaml")
	if err := os.WriteFile(toolPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	decryptCmd := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", toolPath)
	decryptCmd.Env = env
	decrypted, err := decryptCmd.Output()
	if err != nil {
		t.Fatalf("the sops binary could not decrypt what the tool wrote: %v", err)
	}
	if !strings.Contains(string(decrypted), "s3cret") {
		t.Errorf("the sops binary decrypted to:\n%s", decrypted)
	}

	// The sops binary writes, the tool reads.
	plainPath := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(plainPath, []byte("TOKEN: from-cli\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cliPath := filepath.Join(dir, "cli.yaml")
	cmd := exec.Command("sops", "--encrypt", "--age", recipient, "--encrypted-regex", ".*",
		"--input-type", "yaml", "--output-type", "yaml", plainPath)
	cmd.Env = env
	cliRaw, err := cmd.Output()
	if err != nil {
		t.Fatalf("the sops binary could not encrypt: %v", err)
	}
	if err := os.WriteFile(cliPath, cliRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	fromCLI, err := sops.Decrypt(context.Background(), cliRaw, []payload.Identity{identity})
	if err != nil {
		t.Fatalf("the tool could not decrypt what the sops binary wrote: %v", err)
	}
	if fromCLI["TOKEN"] != "from-cli" {
		t.Errorf("TOKEN = %v, want from-cli", fromCLI["TOKEN"])
	}
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
