package groups_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
)

// TestDiscover checks that the groups and the machines are found, in the order
// of the access file.
func TestDiscover(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "access.yaml"), `machines:
  laura:
    age: [age1laura]
  leela:
    age: [age1leela]
groups:
  common:
    - laura
    - leela
  home:
    - laura
`)
	write(t, filepath.Join(dir, "groups", "common", "tokens.sops.yaml"), "TOKEN: x\n")
	write(t, filepath.Join(dir, "groups", "home", "tokens.sops.yaml"), "TOKEN: x\n")
	write(t, filepath.Join(dir, "machines", "laura", "personal.sops.yaml"), "X: y\n")

	layout, err := groups.Discover(dir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if len(layout.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(layout.Groups))
	}
	// The order of the access file is the merge order.
	if layout.Groups[0].Name != "common" || layout.Groups[1].Name != "home" {
		t.Errorf("the groups are not in the order of the access file: %v", layout.Groups)
	}
	if len(layout.Machines) != 2 {
		t.Fatalf("machines = %d, want 2", len(layout.Machines))
	}
	if layout.Machines[0].Name != "laura" {
		t.Errorf("the machines are not in the order of the access file: %v", layout.Machines)
	}
}

// TestDiscoverDerivesRecipients checks that the recipients of a group are
// the keys of its members.
//
// The keys are never written twice: they are only in the machines section.
func TestDiscoverDerivesRecipients(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "access.yaml"), `machines:
  laura:
    age: [age1laura, age1laura2]
  leela:
    age: [age1leela]
groups:
  home:
    - laura
    - leela
`)

	layout, err := groups.Discover(dir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	group := layout.Groups[0]
	want := []string{"age1laura", "age1laura2", "age1leela"}
	if len(group.Recipients) != len(want) {
		t.Fatalf("the recipients = %v, want %v", group.Recipients, want)
	}
	for i, key := range want {
		if group.Recipients[i] != key {
			t.Errorf("the recipient %d = %q, want %q", i, group.Recipients[i], key)
		}
	}
}

// TestDiscoverRejectsADirectoryWithoutAnEntry checks that a directory
// without an entry in the access file is an error.
//
// A directory without an entry would either be readable by nobody or by
// everybody, and neither is ever meant.
func TestDiscoverRejectsADirectoryWithoutAnEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "access.yaml"), `machines:
  laura:
    age: [age1laura]
groups:
  home:
    - laura
`)
	write(t, filepath.Join(dir, "machines", "laura", "x.sops.yaml"), "A: b\n")
	write(t, filepath.Join(dir, "machines", "forgotten", "x.sops.yaml"), "A: b\n")

	if _, err := groups.Discover(dir); err == nil {
		t.Error("a directory without an entry should be an error")
	}
}

// TestDiscoverRejectsAnUnknownMember checks that a group cannot list a
// machine that does not exist.
func TestDiscoverRejectsAnUnknownMember(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "access.yaml"), `machines:
  laura:
    age: [age1laura]
groups:
  home:
    - laura
    - forgotten
`)

	if _, err := groups.Discover(dir); err == nil {
		t.Error("a group with an unknown member should be an error")
	}
}

// TestPayloads checks that the payload files are found in alphabetical
// order, which decides which value wins.
func TestPayloads(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "b.sops.yaml"), "B: 1\n")
	write(t, filepath.Join(dir, "a.sops.yaml"), "A: 1\n")
	write(t, filepath.Join(dir, ".hidden"), "x\n")

	files, err := groups.Payloads(dir)
	if err != nil {
		t.Fatalf("payloads: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("the payloads = %v, want two", files)
	}
	if filepath.Base(files[0]) != "a.sops.yaml" {
		t.Errorf("the payloads are not sorted: %v", files)
	}
}

// TestMachineForHostname checks how a machine is matched to a machine.
//
// The explicit hostnames win. Without them the name is matched, first
// exactly and then by prefix, which is the convention the recipient
// registry used.
func TestMachineForHostname(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "access.yaml"), `machines:
  laura:
    age: [age1laura]
  "SE-CND235268L / worklaptop":
    age: [age1work]
  win:
    hostnames: [SE-CND12345]
    age: [age1win]
`)

	layout, err := groups.Discover(dir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	// An exact match.
	machine, ok := layout.ForHostname("laura")
	if !ok || machine.Name != "laura" {
		t.Errorf("laura = %v, %v", machine.Name, ok)
	}

	// The prefix convention.
	machine, ok = layout.ForHostname("SE-CND235268L")
	if !ok || machine.Name != "SE-CND235268L / worklaptop" {
		t.Errorf("SE-CND235268L = %v, %v", machine.Name, ok)
	}

	// An explicit hostname wins over the name.
	machine, ok = layout.ForHostname("SE-CND12345")
	if !ok || machine.Name != "win" {
		t.Errorf("SE-CND12345 = %v, %v", machine.Name, ok)
	}

	// An unknown machine.
	if _, ok := layout.ForHostname("unknown"); ok {
		t.Error("an unknown machine should not match a machine")
	}
}

// write writes a file, failing the test if it cannot.
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
