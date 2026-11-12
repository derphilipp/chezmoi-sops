package groups_test

import (
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
)

// TestMergeRealBeforeShape checks the rule that matters most: a shape can
// never shadow a value the machine is allowed to read.
//
// The "default" group is decrypted and holds the value, the "other" group is
// not and holds the shape of the same key.
func TestMergeRealBeforeShape(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{
			{Name: "default"},
			{Name: "other"},
		},
	}

	values := map[string]map[string]any{
		"default": {"TOKEN": "the real value"},
		"other":   {"TOKEN": ""},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
		"other":   {Group: "other", Available: false},
	}

	result := groups.Merge(registry, values, status)

	if got := result.Tree["TOKEN"]; got != "the real value" {
		t.Errorf("TOKEN = %v, want the real value", got)
	}
	if got := result.Flat["TOKEN"]; got != "the real value" {
		t.Errorf("TOKEN = %q, want the real value", got)
	}
}

// TestMergeFirstGroupWins checks that the first group wins a conflict.
func TestMergeFirstGroupWins(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{
			{Name: "default"},
			{Name: "other"},
		},
	}

	values := map[string]map[string]any{
		"default": {"TOKEN": "first"},
		"other":   {"TOKEN": "second"},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
		"other":   {Group: "other", Available: true},
	}

	result := groups.Merge(registry, values, status)

	if got := result.Tree["TOKEN"]; got != "first" {
		t.Errorf("TOKEN = %v, want the value of the first group", got)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("the conflict should be reported, got %v", result.Warnings)
	}
}

// TestMergeShapeFillsTheGap checks that a shape contributes the keys that
// no readable group has.
func TestMergeShapeFillsTheGap(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{
			{Name: "default"},
			{Name: "other"},
		},
	}

	values := map[string]map[string]any{
		"default": {"TOKEN": "real"},
		"other":   {"OTHER": ""},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
		"other":   {Group: "other", Available: false},
	}

	result := groups.Merge(registry, values, status)

	if got := result.Tree["TOKEN"]; got != "real" {
		t.Errorf("TOKEN = %v, want real", got)
	}
	if got, ok := result.Tree["OTHER"]; !ok || got != "" {
		t.Errorf("OTHER = %v, want an empty value", got)
	}
}

// TestMergeNestedSecrets checks that nested secrets are merged and
// flattened the way the templates expect.
func TestMergeNestedSecrets(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{{Name: "default"}},
	}

	values := map[string]map[string]any{
		"default": {
			"database": map[string]any{
				"host":     "db.example.com",
				"password": "hunter2",
			},
			"PLAIN": "value",
		},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
	}

	result := groups.Merge(registry, values, status)

	if got := result.Flat["DATABASE_HOST"]; got != "db.example.com" {
		t.Errorf("DATABASE_HOST = %q, want db.example.com", got)
	}
	if got := result.Flat["DATABASE_PASSWORD"]; got != "hunter2" {
		t.Errorf("DATABASE_PASSWORD = %q, want hunter2", got)
	}
	if got := result.Flat["PLAIN"]; got != "value" {
		t.Errorf("PLAIN = %q, want value", got)
	}
}

// TestMergeSkipsInvalidNames checks that a secret that cannot be an
// environment variable is skipped and reported.
func TestMergeSkipsInvalidNames(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{{Name: "default"}},
	}

	values := map[string]map[string]any{
		"default": {"not a valid name": "value"},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
	}

	result := groups.Merge(registry, values, status)

	if len(result.Flat) != 0 {
		t.Errorf("the secret should be skipped, got %v", result.Flat)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("the secret should be reported, got %v", result.Warnings)
	}
}

// TestMergeKeepsGroupValues checks that the values of each group survive
// the merge, so a template can look at one group.
func TestMergeKeepsGroupValues(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{
			{Name: "default"},
			{Name: "other"},
		},
	}

	values := map[string]map[string]any{
		"default": {"TOKEN": "real"},
		"other":   {"TOKEN": ""},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
		"other":   {Group: "other", Available: false},
	}

	result := groups.Merge(registry, values, status)

	if len(result.GroupValues) != 2 {
		t.Fatalf("the group values should be kept, got %v", result.GroupValues)
	}
	if result.GroupValues["default"]["TOKEN"] != "real" {
		t.Errorf("the default group should keep its value")
	}
}
