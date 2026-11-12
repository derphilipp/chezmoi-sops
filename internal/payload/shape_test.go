package payload_test

import (
	"context"
	"testing"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// TestShapeBlanksNestedValues checks that the shape of a nested document is
// blanked all the way down.
//
// The YAML library decodes a nested mapping into a Document rather than a
// plain map, so a type switch on map[string]any alone would leave the
// nested values encrypted in the shape.
func TestShapeBlanksNestedValues(t *testing.T) {
	t.Parallel()

	_, recipient := testIdentity(t)

	doc := payload.Document{
		"TOP": "secret",
		"NESTED": map[string]any{
			"INNER": "secret",
			"DEEPER": map[string]any{
				"DEEPEST": "secret",
			},
		},
		"LIST": []any{"secret", "also secret"},
	}

	sops := payload.NewSOPS()
	raw, err := sops.Encrypt(context.Background(), doc, []string{recipient})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	shape, err := sops.Shape(raw)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}

	if shape["TOP"] != "" {
		t.Errorf("TOP = %v, want an empty value", shape["TOP"])
	}

	nested, ok := payload.AsMap(shape["NESTED"])
	if !ok {
		t.Fatalf("NESTED = %T, want a map", shape["NESTED"])
	}
	if nested["INNER"] != "" {
		t.Errorf("NESTED.INNER = %v, want an empty value", nested["INNER"])
	}

	deeper, ok := payload.AsMap(nested["DEEPER"])
	if !ok {
		t.Fatalf("NESTED.DEEPER = %T, want a map", nested["DEEPER"])
	}
	if deeper["DEEPEST"] != "" {
		t.Errorf("NESTED.DEEPER.DEEPEST = %v, want an empty value", deeper["DEEPEST"])
	}
}

// TestAsMap checks that both map types are recognised.
func TestAsMap(t *testing.T) {
	t.Parallel()

	if _, ok := payload.AsMap(map[string]any{"a": "b"}); !ok {
		t.Error("a plain map should be a map")
	}
	if _, ok := payload.AsMap(payload.Document{"a": "b"}); !ok {
		t.Error("a document should be a map")
	}
	if _, ok := payload.AsMap("a"); ok {
		t.Error("a string should not be a map")
	}
}
