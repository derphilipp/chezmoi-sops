package groups_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
)

// TestDiscover checks that the groups are found, that "default" comes first,
// and that a recipients file without a payload is not a group.
func TestDiscover(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, filepath.Join(dir, "default.recipients.txt"), "age1aaa\n")
	write(t, filepath.Join(dir, "default.sops.yaml"), "TOKEN: x\n")
	write(t, filepath.Join(dir, "zebra.recipients.txt"), "age1bbb\n")
	write(t, filepath.Join(dir, "zebra.yaml.age"), "blob\n")
	write(t, filepath.Join(dir, "alpha.recipients.txt"), "age1ccc\n")
	write(t, filepath.Join(dir, "alpha.sops.yaml"), "TOKEN: x\n")
	// No payload: not a group.
	write(t, filepath.Join(dir, "orphan.recipients.txt"), "age1ddd\n")
	// Not a recipients file at all.
	write(t, filepath.Join(dir, "notes.txt"), "hello\n")

	registry, err := groups.Discover(dir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	want := []string{"default", "alpha", "zebra"}
	got := registry.Names()
	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("group %d = %q, want %q", i, got[i], name)
		}
	}

	// The sops payload wins over the age payload.
	group, _ := registry.Get("zebra")
	if group.Format.Name() != "age" {
		t.Errorf("the zebra group uses the %s format, want age", group.Format.Name())
	}
}

// TestDiscoverEmpty checks that a missing directory is not an error.
func TestDiscoverEmpty(t *testing.T) {
	t.Parallel()

	registry, err := groups.Discover(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(registry.Groups) != 0 {
		t.Errorf("groups = %v, want none", registry.Groups)
	}
}

// TestHostRegistry checks the recipient registry: the comments name the
// machine each key belongs to.
func TestHostRegistry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "default.recipients.txt")
	write(t, path, `# laura
age1laura

# SE-CND235268L / worklaptop
age1work

# grumpysnail
age1grumpy
age1grumpy2
`)

	registry, err := groups.ParseHostRegistry(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	hosts := registry.HostsForKey("age1laura")
	if len(hosts) != 1 || hosts[0] != "laura" {
		t.Errorf("the hosts of age1laura = %v, want [laura]", hosts)
	}

	// A machine with several keys gets all of them.
	keys := registry.KeysForHost("grumpysnail")
	if len(keys) != 2 {
		t.Errorf("the keys of grumpysnail = %v, want two", keys)
	}

	// A prefix match finds the machine.
	keys = registry.KeysForHost("se-cnd235268l")
	if len(keys) != 1 || keys[0] != "age1work" {
		t.Errorf("the keys of se-cnd235268l = %v, want [age1work]", keys)
	}

	// An exact match wins over a prefix match.
	keys = registry.KeysForHost("grumpysnail2")
	if len(keys) != 0 {
		t.Errorf("the keys of grumpysnail2 = %v, want none", keys)
	}
}

// TestHostRegistryEntries checks that the entries are sorted, so the output
// of "chezmoi sops groups" is stable.
func TestHostRegistryEntries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "default.recipients.txt")
	write(t, path, `# zeta
age1zeta

# alpha
age1alpha
`)

	registry, err := groups.ParseHostRegistry(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	entries := registry.Entries()
	if len(entries) != 2 {
		t.Fatalf("entries = %v, want two", entries)
	}
	if entries[0].Host != "alpha" || entries[1].Host != "zeta" {
		t.Errorf("the entries are not sorted: %v", entries)
	}
}

// write writes a file, failing the test if it cannot.
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
