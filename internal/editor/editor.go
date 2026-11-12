// Package editor implements the decrypt, edit, re-encrypt round trip.
package editor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// ErrNoEditor is returned when no editor could be found.
var ErrNoEditor = errors.New("no editor found: set $VISUAL or $EDITOR")

// Editor decrypts a payload, opens it in an editor, and encrypts it again.
type Editor struct {
	// Command is the editor to run. When empty, $VISUAL and $EDITOR are
	// used, and nano is the fallback.
	Command string
}

// Editor returns the editor command to run.
//
// $VISUAL wins over $EDITOR, which is the convention every other tool
// follows.
func (e Editor) Editor() (string, error) {
	if e.Command != "" {
		return e.Command, nil
	}
	for _, env := range []string{"VISUAL", "EDITOR"} {
		if value := strings.TrimSpace(os.Getenv(env)); value != "" {
			return value, nil
		}
	}
	if _, err := exec.LookPath("nano"); err == nil {
		return "nano", nil
	}
	return "", ErrNoEditor
}

// Options configure one edit round trip.
type Options struct {
	// Format is the payload format to write.
	Format payload.Payload

	// Recipients are the age public keys to encrypt for.
	Recipients []string

	// Identities are the age private keys to decrypt with.
	Identities []payload.Identity

	// Force overwrites the payload without decrypting it first.
	Force bool

	// Template is the initial content of a new payload.
	Template []byte
}

// Result describes what an edit round trip did.
type Result struct {
	// Created is true when the payload did not exist before.
	Created bool

	// Converted is true when the payload changed its format.
	Converted bool

	// Empty is true when the payload ended up empty.
	Empty bool
}

// Edit decrypts the payload at path, opens it in the editor, and encrypts it
// again.
//
// The payload is only written when the editor exits successfully. If the
// editor fails, the decrypted content is left in a temporary file so nothing
// is lost.
func (e Editor) Edit(ctx context.Context, path string, opts Options) (Result, error) {
	result := Result{}

	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if !opts.Force {
			decrypted, err := opts.Format.Decrypt(ctx, existing, opts.Identities)
			if err != nil {
				return result, fmt.Errorf(
					"cannot decrypt %s: is this machine a recipient of this group? "+
						"Use --force to overwrite the payload anyway: %w", path, err)
			}
			existing = mustMarshal(decrypted)
		} else {
			// The payload is overwritten, but the old one is still a sops
			// document, so its metadata has to be stripped before it can be
			// edited. What is left are the key names of the old secrets,
			// which is the useful part of the shape.
			existing = stripMetadata(opts.Format, existing)
		}
	case os.IsNotExist(err):
		result.Created = true
		existing = opts.Template
	default:
		return result, fmt.Errorf("reading %s: %w", path, err)
	}

	if len(existing) == 0 {
		existing = opts.Template
	}

	temp, err := os.CreateTemp("", "chezmoi-sops-*.yaml")
	if err != nil {
		return result, fmt.Errorf("creating a temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if _, err := temp.Write(existing); err != nil {
		temp.Close()
		return result, fmt.Errorf("writing the temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return result, fmt.Errorf("closing the temporary file: %w", err)
	}

	editor, err := e.Editor()
	if err != nil {
		return result, err
	}

	// The editor is not run through a shell, so the arguments have to be
	// split here.
	parts := strings.Fields(editor)
	cmd := exec.CommandContext(ctx, parts[0], append(parts[1:], tempPath)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("the editor failed, nothing was changed: %w", err)
	}

	edited, err := os.ReadFile(tempPath)
	if err != nil {
		return result, fmt.Errorf("reading the edited file: %w", err)
	}

	if isEmpty(edited) {
		// An empty document cannot be encrypted: sops needs at least one
		// entry.
		edited = opts.Template
		result.Empty = true
	}

	encrypted, err := opts.Format.Encrypt(ctx, mustParse(edited), opts.Recipients)
	if err != nil {
		return result, fmt.Errorf("encrypting the payload, the plaintext is at %s: %w", tempPath, err)
	}

	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		return result, fmt.Errorf("writing %s: %w", path, err)
	}

	return result, nil
}

// mustMarshal serialises a document back into plain YAML.
func mustMarshal(doc payload.Document) []byte {
	out, err := payload.Marshal(doc)
	if err != nil {
		return nil
	}
	return out
}

// mustParse parses a plain YAML document.
func mustParse(raw []byte) payload.Document {
	doc, err := payload.Parse(raw)
	if err != nil {
		return payload.Document{}
	}
	return doc
}

// stripMetadata removes the sops metadata from a payload, so an encrypted
// document can be edited as a plain one.
//
// For the sops format this leaves the key names with their encrypted values
// replaced by nothing, which is the shape of the group. For the age format
// there is nothing to strip: the document is one opaque blob, so it is
// replaced by an empty document.
func stripMetadata(format payload.Payload, raw []byte) []byte {
	shape, err := format.Shape(raw)
	if err != nil {
		return DefaultTemplate
	}

	out, err := payload.Marshal(shape)
	if err != nil {
		return DefaultTemplate
	}
	return out
}

// isEmpty reports whether the content has nothing but comments and blank
// lines.
func isEmpty(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return false
	}
	return true
}

// DefaultTemplate is the content of a new payload.
var DefaultTemplate = []byte("# One secret per line. The key is the environment variable name.\n{}\n")

// TemplatePath returns the path of the temporary file of an edit, for
// debugging.
func TemplatePath(dir, name string) string {
	return filepath.Join(dir, name)
}
