package access_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/access"
)

// TestLoadKeepsTheOrder checks that the order of the machines and the groups
// is preserved.
//
// The order decides which value wins when two of them hold the same key.
func TestLoadKeepsTheOrder(t *testing.T) {
	t.Parallel()

	path := write(t, `machines:
  zebra:
    age: [age1z]
  alpha:
    age: [age1a]
groups:
  home:
    - alpha
  common:
    - zebra
    - alpha
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(file.Machines) != 2 || file.Machines[0].Name != "zebra" || file.Machines[1].Name != "alpha" {
		t.Errorf("the machines are not in order: %v", file.Machines)
	}
	if len(file.Groups) != 2 || file.Groups[0].Name != "home" || file.Groups[1].Name != "common" {
		t.Errorf("the groups are not in order: %v", file.Groups)
	}
}

// TestLoadAcceptsASingleKey checks that a machine with one key can be
// written without a list.
func TestLoadAcceptsASingleKey(t *testing.T) {
	t.Parallel()

	path := write(t, `machines:
  laura:
    age: age1laura
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(file.Machines[0].Age) != 1 || file.Machines[0].Age[0] != "age1laura" {
		t.Errorf("the age keys = %v, want [age1laura]", file.Machines[0].Age)
	}
}

// TestLoadRejectsAnUnknownMember checks that a group cannot list a machine
// that does not exist.
//
// A key without a name is a key nobody knows the owner of.
func TestLoadRejectsAnUnknownMember(t *testing.T) {
	t.Parallel()

	path := write(t, `machines:
  laura:
    age: [age1laura]
groups:
  home:
    - laura
    - forgotten
`)

	if _, err := access.Load(path); err == nil {
		t.Error("a group with an unknown member should be an error")
	}
}

// TestLoadRejectsAMachineWithoutAKey checks that a machine without a key is
// an error: it could not read anything.
func TestLoadRejectsAMachineWithoutAKey(t *testing.T) {
	t.Parallel()

	path := write(t, `machines:
  laura:
    label: no key
`)

	if _, err := access.Load(path); err == nil {
		t.Error("a machine without a key should be an error")
	}
}

// TestLoadRejectsADuplicate checks that a name is only used once.
func TestLoadRejectsADuplicate(t *testing.T) {
	t.Parallel()

	path := write(t, `machines:
  laura:
    age: [age1laura]
  laura:
    age: [age1other]
`)

	if _, err := access.Load(path); err == nil {
		t.Error("a duplicate machine should be an error")
	}
}

// TestMatchesHostname checks how a machine is matched to a machine.
func TestMatchesHostname(t *testing.T) {
	t.Parallel()

	path := write(t, `machines:
  laura:
    age: [age1laura]
  "SE-CND235268L / worklaptop":
    age: [age1work]
  win:
    hostnames: [SE-CND12345]
    age: [age1win]
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	laura, _ := file.Machine("laura")
	if !laura.MatchesHostname("laura") {
		t.Error("laura should match the hostname laura")
	}
	if !laura.MatchesHostname("LAURA") {
		t.Error("the hostname should be matched case insensitively")
	}
	// The convention is that the hostname is a prefix of the name, so a
	// short hostname matches a longer name too.
	if !laura.MatchesHostname("laur") {
		t.Error("laura should match the hostname laur by the prefix convention")
	}

	work, _ := file.Machine("SE-CND235268L / worklaptop")
	if !work.MatchesHostname("SE-CND235268L") {
		t.Error("the worklaptop should match the hostname SE-CND235268L")
	}

	win, _ := file.Machine("win")
	if !win.MatchesHostname("SE-CND12345") {
		t.Error("the explicit hostname should win")
	}
	if win.MatchesHostname("win") {
		t.Error("the explicit hostnames replace the name")
	}
}

// write writes an access file and returns its path.
func write(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadReadsTheOldHostsSection checks that a file written before 0.5.0 is
// still read, and that saving it writes the new name.
//
// The change of the name is a change of the file, so a machine that has not
// been updated yet has to be able to read a repository that has.
func TestLoadReadsTheOldHostsSection(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
  laura:
    age: [age1laura]
groups:
  common:
    - laura
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(file.Machines) != 1 || file.Machines[0].Name != "laura" {
		t.Errorf("the machines were not read: %v", file.Machines)
	}

	// Changing the file writes the new name, so the old one disappears.
	if err := file.AddGroup("home", []string{"laura"}); err != nil {
		t.Fatalf("add group: %v", err)
	}
	if err := file.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "machines:") {
		t.Errorf("the file was not written with the new name:\n%s", saved)
	}
	if strings.Contains(string(saved), "hosts:") {
		t.Errorf("the old name is still in the file:\n%s", saved)
	}
}
