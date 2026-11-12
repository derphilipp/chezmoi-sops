package access_test

import (
	"os"
	"strings"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/access"
)

// TestSaveKeepsTheComments checks that editing the access file does not
// lose the comments in it.
//
// The access file is meant to be read and edited by a human, so nothing in
// it may be lost.
func TestSaveKeepsTheComments(t *testing.T) {
	t.Parallel()

	path := write(t, `# The access file
hosts:
  # the boss
  laura:
    age:
      - age1laura
groups:
  common:
    - laura
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if err := file.SetGroupMembers("common", []string{"laura", "leela"}); err != nil {
		t.Fatalf("set members: %v", err)
	}
	if err := file.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	content := read(t, path)
	for _, comment := range []string{"# The access file", "# the boss"} {
		if !strings.Contains(content, comment) {
			t.Errorf("the comment %q was lost:\n%s", comment, content)
		}
	}
	if !strings.Contains(content, "leela") {
		t.Errorf("the new member was not written:\n%s", content)
	}
}

// TestAddAndRemove checks that the entries can be added and removed.
func TestAddAndRemove(t *testing.T) {
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

	if err := file.AddHost("leela", []string{"age1leela"}); err != nil {
		t.Fatalf("add host: %v", err)
	}
	if err := file.AddGroup("work", []string{"leela"}); err != nil {
		t.Fatalf("add group: %v", err)
	}
	if err := file.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := access.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := reloaded.Host("leela"); !ok {
		t.Error("the host was not written")
	}
	if _, ok := reloaded.Group("work"); !ok {
		t.Error("the group was not written")
	}

	// The recipients of a group are the keys of its members.
	recipients := reloaded.RecipientsOf("work")
	if len(recipients) != 1 || recipients[0] != "age1leela" {
		t.Errorf("the recipients of work = %v, want [age1leela]", recipients)
	}

	if err := reloaded.RemoveHost("leela"); err != nil {
		t.Fatalf("remove host: %v", err)
	}
	if err := reloaded.RemoveGroup("work"); err != nil {
		t.Fatalf("remove group: %v", err)
	}
	if err := reloaded.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	content := read(t, path)
	if strings.Contains(content, "leela") {
		t.Errorf("the host was not removed:\n%s", content)
	}
}

// TestRecipientsOf checks that the recipients of a group are the keys of
// its members.
func TestRecipientsOf(t *testing.T) {
	t.Parallel()

	path := write(t, `hosts:
  laura:
    age: [age1laura, age1laura2]
  leela:
    age: [age1leela]
groups:
  home:
    - laura
    - leela
`)

	file, err := access.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	recipients := file.RecipientsOf("home")
	want := []string{"age1laura", "age1laura2", "age1leela"}
	if len(recipients) != len(want) {
		t.Fatalf("the recipients = %v, want %v", recipients, want)
	}
	for i, key := range want {
		if recipients[i] != key {
			t.Errorf("the recipient %d = %q, want %q", i, recipients[i], key)
		}
	}
}

// read reads a file.
func read(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
