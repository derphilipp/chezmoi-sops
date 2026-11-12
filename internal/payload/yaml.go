package payload

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Marshal serialises a document into plain YAML.
func Marshal(doc Document) ([]byte, error) {
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshalling document: %w", err)
	}
	return out, nil
}

// Parse parses a plain YAML document.
func Parse(raw []byte) (Document, error) {
	var doc Document
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}
	return doc, nil
}
