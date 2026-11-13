package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGroupList checks that the groups are listed.
func TestGroupList(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "group", "list")

	if !strings.Contains(out, "common") {
		t.Errorf("the output does not mention the group:\n%s", out)
	}
}

// TestGroupMembers checks that the members of a group are listed.
func TestGroupMembers(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "group", "members", "common")

	for _, machine := range []string{"laura", "leela"} {
		if !strings.Contains(out, machine) {
			t.Errorf("the output does not mention %q:\n%s", machine, out)
		}
	}
}

// TestGroupAdd checks that a machine is added to a group.
func TestGroupAdd(t *testing.T) {
	dir := testLayout(t)
	run(t, dir, "group", "add", "common", "matnix")
	out := run(t, dir, "group", "members", "common")

	if !strings.Contains(out, "matnix") {
		t.Errorf("the output does not mention the machine:\n%s", out)
	}
}

// TestGroupRemove checks that a machine is removed from a group.
func TestGroupRemove(t *testing.T) {
	dir := testLayout(t)
	run(t, dir, "group", "remove", "common", "leela")
	out := run(t, dir, "group", "members", "common")

	if strings.Contains(out, "leela") {
		t.Errorf("the output still mentions the machine:\n%s", out)
	}
	if !strings.Contains(out, "laura") {
		t.Errorf("the output does not mention the other machine:\n%s", out)
	}
}

// TestMachineList checks that the machines and their keys are listed.
func TestMachineList(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "machine", "list")

	for _, key := range []string{"laura", "age1laura", "leela", "age1leela"} {
		if !strings.Contains(out, key) {
			t.Errorf("the output does not mention %q:\n%s", key, out)
		}
	}
}

// TestMachineKeys checks that the keys of one machine are listed.
func TestMachineKeys(t *testing.T) {
	dir := testLayout(t)
	out := run(t, dir, "machine", "keys", "laura")

	if !strings.Contains(out, "age1laura") {
		t.Errorf("the output does not mention the key:\n%s", out)
	}
	if strings.Contains(out, "age1leela") {
		t.Errorf("the output mentions another machine:\n%s", out)
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

	access := `machines:
  laura:
    age:
      - age1laura
  leela:
    age:
      - age1leela
  matnix:
    age:
      - age1matnix
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

	// The access file is copied once: the commands that change it have to
	// keep their change for the commands that come after them.
	sourceAccess := filepath.Join(source, ".secrets", "access.yaml")
	if _, err := os.Stat(sourceAccess); os.IsNotExist(err) {
		content, err := os.ReadFile(filepath.Join(dir, ".secrets", "access.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sourceAccess, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	full := append([]string{"--source-dir", source}, args...)

	var stdout bytes.Buffer
	if err := execute(full, &stdout, io.Discard); err != nil {
		t.Fatalf("%v: %s", args, err)
	}
	return stdout.String()
}
