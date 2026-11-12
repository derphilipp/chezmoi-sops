package payload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// Age is the whole-file age payload format: the whole document is encrypted
// into one opaque blob.
//
// It has no shape: once the document is encrypted there is nothing left to
// read, so a machine that cannot decrypt the group contributes nothing at
// all.
type Age struct{}

// NewAge returns the whole-file age payload format.
func NewAge() *Age { return &Age{} }

// Name implements Payload.
func (a *Age) Name() string { return "age" }

// Decrypt implements Payload.
func (a *Age) Decrypt(_ context.Context, raw []byte, identities []Identity) (Document, error) {
	if len(identities) == 0 {
		return nil, errors.New("no identity available")
	}

	// Every identity gets a fresh reader: age consumes the stream while it
	// looks for the matching stanza, so a reader that was used for a
	// failed attempt cannot be reused.
	var decrypted []byte
	for _, identity := range identities {
		key, err := age.ParseX25519Identity(identity.PrivateKey())
		if err != nil {
			continue
		}

		var reader io.Reader = bytes.NewReader(raw)
		if bytes.HasPrefix(raw, []byte(armorHeader)) {
			reader = armorReader(reader)
		}

		out, err := age.Decrypt(reader, key)
		if err != nil {
			continue
		}
		decrypted, err = io.ReadAll(out)
		if err != nil {
			return nil, fmt.Errorf("reading decrypted document: %w", err)
		}
		break
	}

	if decrypted == nil {
		return nil, errors.New("could not decrypt the payload with the available identities")
	}

	var doc Document
	if err := yaml.Unmarshal(decrypted, &doc); err != nil {
		return nil, fmt.Errorf("parsing decrypted document: %w", err)
	}
	return doc, nil
}

// Encrypt implements Payload.
func (a *Age) Encrypt(_ context.Context, doc Document, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients given")
	}

	plaintext, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshalling document: %w", err)
	}

	parsed := make([]age.Recipient, 0, len(recipients))
	for _, recipient := range recipients {
		r, err := age.ParseX25519Recipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient %q: %w", recipient, err)
		}
		parsed = append(parsed, r)
	}

	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, parsed...)
	if err != nil {
		return nil, fmt.Errorf("encrypting document: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing document: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing document: %w", err)
	}
	return buf.Bytes(), nil
}

// Shape implements Payload. The age format has no shape.
func (a *Age) Shape(_ []byte) (Document, error) {
	return nil, ErrNoShape
}

// armorHeader is the first line of an ASCII-armored age file.
const armorHeader = "-----BEGIN AGE ENCRYPTED FILE-----"

// armorReader wraps r in an armor reader.
func armorReader(r io.Reader) io.Reader {
	return armor.NewReader(r)
}

// ParseIdentities reads age identities from a file, ignoring comments and
// blank lines.
func ParseIdentities(path string) ([]Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	parsed, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parsing identities from %s: %w", path, err)
	}

	identities := make([]Identity, 0, len(parsed))
	for _, id := range parsed {
		x25519, ok := id.(*age.X25519Identity)
		if !ok {
			continue
		}
		identities = append(identities, &AgeIdentity{identity: x25519})
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no usable age identity in %s", path)
	}
	return identities, nil
}

// Recipients implements Payload.
//
// The whole-file age format cannot tell: the recipients are inside the
// encrypted blob, so there is nothing to read without the key.
func (a *Age) Recipients(_ []byte) ([]string, error) {
	return nil, nil
}
