// Package keyring finds the age identity that this machine uses.
//
// The identity is not configured in the tool: chezmoi's own config is the
// single source of truth, so a machine is configured in exactly one place.
package keyring

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// ErrNoIdentity is returned when no age identity could be found.
var ErrNoIdentity = errors.New("no age identity found")

// Keyring resolves the identity used to decrypt payloads.
type Keyring struct {
	// Explicit is the identity file given on the command line.
	Explicit string

	// FromConfig is the identity chezmoi's config points at.
	FromConfig string

	// Env is the value of SOPS_AGE_KEY_FILE.
	Env string
}

// Find returns the identities to decrypt with.
//
// The first source that yields a readable identity file wins:
//
//  1. the --identity flag,
//  2. $SOPS_AGE_KEY_FILE,
//  3. chezmoi's [age] identity,
//  4. the well-known sops locations.
//
// Every readable file is tried in that order, so a machine that keeps its key
// in several places still works.
func (k Keyring) Find() ([]payload.Identity, error) {
	candidates := k.candidates()

	var identities []payload.Identity
	var lastErr error
	found := false

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		found = true

		parsed, err := payload.ParseIdentities(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		identities = append(identities, parsed...)
	}

	if len(identities) > 0 {
		return identities, nil
	}

	if found {
		if lastErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrNoIdentity, lastErr)
		}
		return nil, ErrNoIdentity
	}

	return nil, fmt.Errorf("%w: no identity configured, and none of the default locations exist", ErrNoIdentity)
}

// candidates returns the identity files to try, in order.
func (k Keyring) candidates() []string {
	candidates := []string{k.Explicit, k.Env, k.FromConfig}
	candidates = append(candidates, DefaultPaths()...)
	return candidates
}

// DefaultPaths returns the well-known locations of an age identity.
//
// These are the paths sops itself looks at, so a machine set up for sops
// works with the tool without any extra configuration.
func DefaultPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	paths := []string{
		filepath.Join(home, ".chezmoi-age-identity.txt"),
		filepath.Join(home, ".age", "key.txt"),
		filepath.Join(home, ".config", "sops", "age", "keys.txt"),
	}

	// On Windows sops looks in %AppData%\sops\age\keys.txt.
	if appData := os.Getenv("AppData"); appData != "" {
		paths = append(paths, filepath.Join(appData, "sops", "age", "keys.txt"))
	}

	// XDG_CONFIG_HOME overrides the ~/.config location.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "sops", "age", "keys.txt"))
	}

	return paths
}

// Recipients reads the recipients of a group.
//
// The file is the same format age uses: one recipient per line, with
// comments and blank lines ignored.
func Recipients(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var recipients []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		recipients = append(recipients, line)
	}
	return recipients, nil
}
