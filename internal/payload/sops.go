package payload

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/shamir"
	sopsyaml "github.com/getsops/sops/v3/stores/yaml"
	yamlv3 "gopkg.in/yaml.v3"
)

// sopsVersion is the version string written into the sops metadata. It
// matches the pinned library version.
const sopsVersion = "3.13.3"

// encryptedPrefix marks an encrypted value in a sops document.
const encryptedPrefix = "ENC["

// metadataKey is the key sops uses for its own metadata in the document.
const metadataKey = "sops"

// SOPS is the sops payload format: the values of the document are encrypted
// individually, so the key names stay readable in the repository.
type SOPS struct{}

// NewSOPS returns the sops payload format.
func NewSOPS() *SOPS { return &SOPS{} }

// Name implements Payload.
func (s *SOPS) Name() string { return "sops" }

// store returns the YAML store used to read and write sops documents.
func (s *SOPS) store() *sopsyaml.Store {
	return sopsyaml.NewStore(&config.YAMLStoreConfig{})
}

// Decrypt implements Payload.
func (s *SOPS) Decrypt(_ context.Context, raw []byte, identities []Identity) (Document, error) {
	tree, err := s.store().LoadEncryptedFile(raw)
	if err != nil {
		return nil, fmt.Errorf("loading encrypted document: %w", err)
	}

	dataKey, err := dataKeyFor(tree, identities)
	if err != nil {
		return nil, err
	}

	// Tree.Decrypt decrypts the tree in place and returns the computed MAC.
	// It must therefore run exactly once, before the values are emitted.
	computedMAC, err := tree.Decrypt(dataKey, aes.NewCipher())
	if err != nil {
		return nil, fmt.Errorf("decrypting tree: %w", err)
	}

	if err := checkMAC(tree, dataKey, computedMAC); err != nil {
		return nil, err
	}

	plaintext, err := s.store().EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("writing decrypted document: %w", err)
	}

	var doc Document
	if err := yamlv3.Unmarshal(plaintext, &doc); err != nil {
		return nil, fmt.Errorf("parsing decrypted document: %w", err)
	}
	return doc, nil
}

// Encrypt implements Payload.
func (s *SOPS) Encrypt(_ context.Context, doc Document, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients given")
	}

	plaintext, err := yamlv3.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshalling document: %w", err)
	}

	branches, err := s.store().LoadPlainFile(plaintext)
	if err != nil {
		return nil, fmt.Errorf("loading document: %w", err)
	}

	keyGroup, err := masterKeyGroup(recipients)
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{keyGroup},
			Version:   sopsVersion,
			// Every value is encrypted, not just the ones that look like
			// secrets.
			EncryptedRegex: ".*",
		},
	}

	dataKey, errs := tree.GenerateDataKey()
	if len(errs) > 0 {
		return nil, errs[0]
	}

	// The timestamp is the additional data of the MAC, so it has to be set
	// before the MAC is computed.
	tree.Metadata.LastModified = time.Now().UTC().Truncate(time.Second)

	mac, err := tree.Encrypt(dataKey, aes.NewCipher())
	if err != nil {
		return nil, fmt.Errorf("encrypting tree: %w", err)
	}
	tree.Metadata.MessageAuthenticationCode, err = aes.NewCipher().Encrypt(
		mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encrypting MAC: %w", err)
	}

	out, err := s.store().EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("writing document: %w", err)
	}
	return out, nil
}

// Shape implements Payload. It reads the encrypted document and blanks every
// encrypted value, leaving the key names visible.
func (s *SOPS) Shape(raw []byte) (Document, error) {
	var doc Document
	if err := yamlv3.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}
	delete(doc, metadataKey)

	blanked, _ := blankValues(map[string]any(doc)).(map[string]any)
	return Document(blanked), nil
}

// masterKeyGroup builds the sops key group for the given recipients.
func masterKeyGroup(recipients []string) (sops.KeyGroup, error) {
	group := sops.KeyGroup{}
	for _, recipient := range recipients {
		key, err := sopsage.MasterKeyFromRecipient(recipient)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient %q: %w", recipient, err)
		}
		group = append(group, key)
	}
	return group, nil
}

// dataKeyFor recovers the data key of the tree using the given identities.
//
// The sops key service cannot be used here: it rebuilds the master key from
// its serialised form, which drops the identities that were injected into
// it. The master keys are therefore unwrapped directly.
func dataKeyFor(tree sops.Tree, identities []Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("no identity available")
	}

	// The tree's own key groups do not carry the private keys any more, so
	// the identities have to be applied to them before they can unwrap the
	// data key.
	parsed := sopsage.ParsedIdentities{}
	for _, identity := range identities {
		if err := parsed.Import(identity.PrivateKey()); err != nil {
			return nil, fmt.Errorf("importing identity: %w", err)
		}
	}

	var parts [][]byte
	var errs []error
	for _, keyGroup := range tree.Metadata.KeyGroups {
		part, err := decryptKeyGroup(keyGroup, parsed)
		if err == nil {
			parts = append(parts, part)
			continue
		}
		errs = append(errs, err)
	}

	switch {
	case len(tree.Metadata.KeyGroups) > 1:
		// Shamir secret sharing: every key group holds a share of the data
		// key, and a threshold of them has to be available.
		if len(parts) < tree.Metadata.ShamirThreshold {
			return nil, fmt.Errorf("could not recover the data key: %d of %d key groups decrypted: %w",
				len(parts), tree.Metadata.ShamirThreshold, errors.Join(errs...))
		}
		dataKey, err := shamir.Combine(parts)
		if err != nil {
			return nil, fmt.Errorf("combining the key group shares: %w", err)
		}
		return dataKey, nil
	case len(parts) == 1:
		return parts[0], nil
	default:
		return nil, fmt.Errorf("could not recover the data key: %w", errors.Join(errs...))
	}
}

// decryptKeyGroup unwraps the data key of one key group.
//
// Every key in a group wraps the same data key, so the first one that works
// is enough.
func decryptKeyGroup(group sops.KeyGroup, parsed sopsage.ParsedIdentities) ([]byte, error) {
	var errs []error
	for _, key := range group {
		ageKey, ok := key.(*sopsage.MasterKey)
		if !ok {
			continue
		}
		parsed.ApplyToMasterKey(ageKey)

		dataKey, err := ageKey.Decrypt()
		if err == nil {
			return dataKey, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, errors.New("no age key in this key group")
	}
	return nil, errors.Join(errs...)
}

// checkMAC verifies the message authentication code of the tree.
func checkMAC(tree sops.Tree, dataKey []byte, computedMAC string) error {
	if tree.Metadata.MessageAuthenticationCode == "" {
		return errors.New("MAC mismatch: file has no MAC")
	}

	fileMAC, err := aes.NewCipher().Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("MAC mismatch: cannot decrypt MAC: %w", err)
	}

	if fileMAC != computedMAC {
		return fmt.Errorf("MAC mismatch: file has %s, computed %s", fileMAC, computedMAC)
	}
	return nil
}

// blankValues replaces every encrypted value with an empty string, keeping
// the structure of the document intact.
func blankValues(value any) any {
	switch t := value.(type) {
	case Document:
		out := make(Document, len(t))
		for k, v := range t {
			out[k] = blankValues(v)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[k] = blankValues(v)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = blankValues(v)
		}
		return out
	case string:
		if strings.HasPrefix(t, encryptedPrefix) {
			return ""
		}
		return t
	default:
		return value
	}
}

// AgeIdentity adapts an age identity to the Payload interface.
type AgeIdentity struct {
	identity *age.X25519Identity
}

// NewAgeIdentity parses an age identity from its bech32 representation.
func NewAgeIdentity(s string) (*AgeIdentity, error) {
	id, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, fmt.Errorf("parsing age identity: %w", err)
	}
	return &AgeIdentity{identity: id}, nil
}

// Recipient implements Identity.
func (a *AgeIdentity) Recipient() string {
	return a.identity.Recipient().String()
}

// PrivateKey implements Identity.
func (a *AgeIdentity) PrivateKey() string {
	return a.identity.String()
}
