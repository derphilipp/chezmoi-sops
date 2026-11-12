// Package payload defines the encrypted formats a secret group can use.
//
// A group payload is a YAML document. Two encodings are supported:
//
//   - sops: the values are encrypted individually, the key names stay readable.
//     A machine that cannot decrypt the group still sees the shape.
//   - age: the whole document is encrypted into one opaque blob.
//
// Both are behind the Payload interface so the group model does not care
// which one a group uses.
package payload

import (
	"context"
	"errors"
)

// ErrNoShape is returned when a payload format cannot expose the shape of
// its contents. The whole-file age format cannot: once the document is
// encrypted there is nothing left to read.
var ErrNoShape = errors.New("payload format does not expose a shape")

// ErrUnsupportedFormat is returned when a format name is not known.
var ErrUnsupportedFormat = errors.New("unsupported payload format")

// Payload is an encrypted document.
type Payload interface {
	// Name is the format name, as used on the command line.
	Name() string

	// Decrypt returns the plaintext document. It returns an error when the
	// payload cannot be decrypted, for example because this machine is not
	// a recipient.
	Decrypt(ctx context.Context, raw []byte, identities []Identity) (Document, error)

	// Encrypt encrypts the document for the given recipients.
	Encrypt(ctx context.Context, doc Document, recipients []string) ([]byte, error)

	// Shape returns the document with every value blanked, so the key names
	// remain visible without decrypting anything. It returns ErrNoShape for
	// formats that cannot do this.
	Shape(raw []byte) (Document, error)
}

// Identity is an age private key that can decrypt a payload.
type Identity interface {
	// Recipient returns the public key of this identity.
	Recipient() string

	// PrivateKey returns the bech32-encoded private key. It never leaves
	// the process.
	PrivateKey() string
}

// Document is a parsed YAML document: a tree of maps, sequences and scalars.
type Document map[string]any

// Clone returns a deep copy of the document.
func (d Document) Clone() Document {
	if d == nil {
		return nil
	}
	out := make(Document, len(d))
	for k, v := range d {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = cloneValue(val)
		}
		return out
	case Document:
		return t.Clone()
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = cloneValue(val)
		}
		return out
	default:
		return v
	}
}
