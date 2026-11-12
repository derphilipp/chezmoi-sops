package groups_test

import (
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// TestMergeMergesNestedMaps checks that two groups that hold the same
// nested key are merged, rather than the first one winning wholesale.
//
// The YAML library decodes a nested mapping into a Document rather than a
// plain map, so a type switch on map[string]any alone would miss it.
func TestMergeMergesNestedMaps(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{
			{Name: "default"},
			{Name: "other"},
		},
	}

	values := map[string]map[string]any{
		"default": {
			"database": payload.Document{
				"host": "db.example.com",
			},
		},
		"other": {
			"database": payload.Document{
				"password": "hunter2",
			},
		},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
		"other":   {Group: "other", Available: true},
	}

	result := groups.Merge(registry, values, status)

	database, ok := payload.AsMap(result.Tree["database"])
	if !ok {
		t.Fatalf("database = %T, want a map", result.Tree["database"])
	}
	if database["host"] != "db.example.com" {
		t.Errorf("database.host = %v, want db.example.com", database["host"])
	}
	if database["password"] != "hunter2" {
		t.Errorf("database.password = %v, want hunter2", database["password"])
	}
}

// TestMergeFlattensNestedDocuments checks that a nested document is
// flattened, not stringified.
func TestMergeFlattensNestedDocuments(t *testing.T) {
	t.Parallel()

	registry := groups.Registry{
		Groups: []groups.Group{{Name: "default"}},
	}

	values := map[string]map[string]any{
		"default": {
			"NESTED": payload.Document{
				"INNER": "value",
			},
		},
	}
	status := map[string]groups.Status{
		"default": {Group: "default", Available: true},
	}

	result := groups.Merge(registry, values, status)

	if got := result.Flat["NESTED_INNER"]; got != "value" {
		t.Errorf("NESTED_INNER = %q, want value", got)
	}
	if _, ok := result.Flat["NESTED"]; ok {
		t.Errorf("the nested document should not be flattened as a whole: %v", result.Flat)
	}
}
