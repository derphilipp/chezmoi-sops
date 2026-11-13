package groups_test

import (
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// source builds a readable group.
func group(name string, values map[string]any) groups.Source {
	return groups.Source{
		Kind:             groups.KindGroup,
		Name:             name,
		Values:           values,
		Available:        true,
		Reason:           groups.ReasonAvailable,
		ContributesShape: true,
	}
}

// unreadableGroup builds a group that cannot be decrypted, with a shape.
func unreadableGroup(name string, shape map[string]any) groups.Source {
	return groups.Source{
		Kind:             groups.KindGroup,
		Name:             name,
		Available:        false,
		Reason:           groups.ReasonNotAuthorized,
		Shape:            shape,
		ContributesShape: true,
	}
}

// TestMergeRealBeforeShape checks the rule that matters most: a shape can
// never shadow a value the machine is allowed to read.
func TestMergeRealBeforeShape(t *testing.T) {
	t.Parallel()

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{"TOKEN": "the real value"}),
		unreadableGroup("other", map[string]any{"TOKEN": ""}),
	})

	if got := result.Tree["TOKEN"]; got != "the real value" {
		t.Errorf("TOKEN = %v, want the real value", got)
	}
	if got := result.Flat["TOKEN"]; got != "the real value" {
		t.Errorf("TOKEN = %q, want the real value", got)
	}
}

// TestMergeFirstSourceWins checks that the first source wins a conflict.
func TestMergeFirstSourceWins(t *testing.T) {
	t.Parallel()

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{"TOKEN": "first"}),
		group("other", map[string]any{"TOKEN": "second"}),
	})

	if got := result.Tree["TOKEN"]; got != "first" {
		t.Errorf("TOKEN = %v, want the value of the first source", got)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("the conflict should be reported, got %v", result.Warnings)
	}
}

// TestMergeShapeFillsTheGap checks that a shape contributes the keys that
// no readable source has.
func TestMergeShapeFillsTheGap(t *testing.T) {
	t.Parallel()

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{"TOKEN": "real"}),
		unreadableGroup("other", map[string]any{"OTHER": ""}),
	})

	if got := result.Tree["TOKEN"]; got != "real" {
		t.Errorf("TOKEN = %v, want real", got)
	}
	if got, ok := result.Tree["OTHER"]; !ok || got != "" {
		t.Errorf("OTHER = %v, want an empty value", got)
	}
}

// TestMergeMachineShapeIsNotMerged checks that a machine contributes nothing when
// it cannot be decrypted.
//
// The secrets of a machine are for that machine alone, so their names belong
// to it alone too.
func TestMergeMachineShapeIsNotMerged(t *testing.T) {
	t.Parallel()

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{"TOKEN": "real"}),
		{
			Kind:             groups.KindMachine,
			Name:             "laura",
			Available:        false,
			Reason:           groups.ReasonNotAuthorized,
			Shape:            map[string]any{"PERSONAL": ""},
			ContributesShape: false,
		},
	})

	if _, ok := result.Tree["PERSONAL"]; ok {
		t.Errorf("the shape of a machine should not be merged: %v", result.Tree)
	}
}

// TestMergeNestedSecrets checks that nested secrets are merged and
// flattened the way the templates expect.
func TestMergeNestedSecrets(t *testing.T) {
	t.Parallel()

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{
			"database": map[string]any{
				"host":     "db.example.com",
				"password": "hunter2",
			},
			"PLAIN": "value",
		}),
	})

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

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{"not a valid name": "value"}),
	})

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

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{"TOKEN": "real"}),
		unreadableGroup("other", map[string]any{"TOKEN": ""}),
	})

	if len(result.GroupValues) != 1 {
		t.Fatalf("only the readable groups should be kept, got %v", result.GroupValues)
	}
	if result.GroupValues["common"]["TOKEN"] != "real" {
		t.Errorf("the group should keep its value")
	}
}

// TestMergeMergesNestedMaps checks that two sources that hold the same
// nested key are merged, rather than the first one winning wholesale.
//
// The YAML library decodes a nested mapping into a Document rather than a
// plain map, so a type switch on map[string]any alone would miss it.
func TestMergeMergesNestedMaps(t *testing.T) {
	t.Parallel()

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{
			"database": payload.Document{"host": "db.example.com"},
		}),
		group("other", map[string]any{
			"database": payload.Document{"password": "hunter2"},
		}),
	})

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

	result := groups.Merge([]groups.Source{
		group("common", map[string]any{
			"NESTED": payload.Document{"INNER": "value"},
		}),
	})

	if got := result.Flat["NESTED_INNER"]; got != "value" {
		t.Errorf("NESTED_INNER = %q, want value", got)
	}
	if _, ok := result.Flat["NESTED"]; ok {
		t.Errorf("the nested document should not be flattened as a whole: %v", result.Flat)
	}
}
