package access_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/access"
)

// TestLoadKeepsTheOrder checks that the order of the hosts and the groups
// is preserved.
//
// The order decides which value wins when two of them hold the same key.
func TestLoadKeepsTheOrder(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
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

	if len(file.Hosts) != 2 || file.Hosts[0].Name != "zebra" || file.Hosts[1].Name != "alpha" {
		t.Errorf("the hosts are not in order: %v", file.Hosts)
	}
	if len(file.Groups) != 2 || file.Groups[0].Name != "home" || file.Groups[1].Name != "common" {
		t.Errorf("the groups are not in order: %v", file.Groups)
	}
}

// TestLoadAcceptsASingleKey checks that a machine with one key can be
// written without a list.
func TestLoadAcceptsASingleKey(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
  laura:
    age: age1laura
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(file.Hosts[0].Age) != 1 || file.Hosts[0].Age[0] != "age1laura" {
		t.Errorf("the age keys = %v, want [age1laura]", file.Hosts[0].Age)
	}
}

// TestLoadRejectsAnUnknownMember checks that a group cannot list a host
// that does not exist.
//
// A key without a name is a key nobody knows the owner of.
func TestLoadRejectsAnUnknownMember(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
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

// TestLoadRejectsAHostWithoutAKey checks that a machine without a key is
// an error: it could not read anything.
func TestLoadRejectsAHostWithoutAKey(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
  laura:
    label: no key
`)

	if _, err := access.Load(path); err == nil {
		t.Error("a host without a key should be an error")
	}
}

// TestLoadRejectsADuplicate checks that a name is only used once.
func TestLoadRejectsADuplicate(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
  laura:
    age: [age1laura]
  laura:
    age: [age1other]
`)

	if _, err := access.Load(path); err == nil {
		t.Error("a duplicate host should be an error")
	}
}

// TestMatchesHostname checks how a machine is matched to a host.
func TestMatchesHostname(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
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

	laura, _ := file.Host("laura")
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

	work, _ := file.Host("SE-CND235268L / worklaptop")
	if !work.MatchesHostname("SE-CND235268L") {
		t.Error("the worklaptop should match the hostname SE-CND235268L")
	}

	win, _ := file.Host("win")
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
