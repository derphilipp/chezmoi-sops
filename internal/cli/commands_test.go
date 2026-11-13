package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeysWithoutAMachine checks that the keys of every machine are listed
// when no machine is named.
//
// The command is meant to be usable without arguments, like the other
// commands that show the state of the repository.
func TestKeysWithoutAMachine(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "keys")

	for _, key := range []string{"laura", "age1laura", "leela", "age1leela"} {
		if !strings.Contains(out, key) {
			t.Errorf("the output does not mention %q:\n%s", key, out)
		}
	}
}

// TestKeysOfOneMachine checks that the keys of one machine are listed.
func TestKeysOfOneMachine(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "keys", "laura")

	if !strings.Contains(out, "age1laura") {
		t.Errorf("the output does not mention the key:\n%s", out)
	}
	if strings.Contains(out, "age1leela") {
		t.Errorf("the output mentions another machine:\n%s", out)
	}
}

// TestMembersWithoutAGroup checks that every group is listed when no group
// is named.
func TestMembersWithoutAGroup(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "members")

	if !strings.Contains(out, "common") {
		t.Errorf("the output does not mention the group:\n%s", out)
	}
}

// testLayout writes a small layout and returns its directory.
func testLayout(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	secrets := filepath.Join(dir, ".secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}

	access := `hosts:
  laura:
    age:
      - age1laura
  leela:
    age:
      - age1leela
groups:
  common:
    - laura
    - leela
`
	if err := os.WriteFile(filepath.Join(secrets, "access.yaml"), []byte(access), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

// run runs the command in the given directory and returns its output.
func run(t *testing.T, dir string, args ...string) string {
	t.Helper()

	// The command reads the layout from the source directory, so the
	// directory has to look like a chezmoi source directory.
	source := filepath.Join(dir, "source")
	if err := os.MkdirAll(filepath.Join(source, ".secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dir, ".secrets", "access.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, ".secrets", "access.yaml"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	full := append([]string{"--source-dir", source}, args...)

	var stdout bytes.Buffer
	if err := execute(full, &stdout, io.Discard); err != nil {
		t.Fatalf("%v: %s", args, err)
	}
	return stdout.String()
}
