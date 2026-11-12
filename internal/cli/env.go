package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/derphilipp/chezmoi-sops/internal/chezmoi"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/keyring"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// env is the resolved environment of a command: the chezmoi configuration,
// the groups, and the identity.
type env struct {
	// Config is the chezmoi configuration.
	Config chezmoi.Config

	// Registry is the groups that were found.
	Registry groups.Registry

	// Identities are the age identities of this machine.
	Identities []payload.Identity
}

// resolve reads the chezmoi configuration and finds the groups and the
// identity.
func resolve() (*env, error) {
	config, err := chezmoi.Load()
	if err != nil {
		return nil, err
	}

	if flagSourceDir != "" {
		config.SourceDir = flagSourceDir
	}

	registry, err := groups.Discover(config.SecretsDir())
	if err != nil {
		return nil, err
	}

	keys := keyring.Keyring{
		Explicit:   flagIdentity,
		FromConfig: config.Identity,
	}
	identities, err := keys.Find()
	if err != nil {
		// A missing identity is not fatal: a machine without a key still
		// sees the shape of the groups it cannot read.
		identities = nil
	}

	return &env{
		Config:     config,
		Registry:   registry,
		Identities: identities,
	}, nil
}

// recipientsFor returns the recipients of a group.
//
// The group's own recipients file is the source of truth. The --recipients
// flag overrides it, which is what the recipient registry lookup uses.
func (e *env) recipientsFor(group groups.Group) ([]string, error) {
	path := group.RecipientsPath
	if flagRecipients != "" {
		path = flagRecipients
	}

	recipients, err := keyring.Recipients(path)
	if err != nil {
		return nil, fmt.Errorf("reading the recipients of group %q: %w", group.Name, err)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("group %q has no recipients", group.Name)
	}
	return recipients, nil
}

// payloadPath returns the path of the payload of a group in the given format.
func payloadPath(dir, name, format string) string {
	if format == "age" {
		return filepath.Join(dir, name+groups.AgePayloadSuffix)
	}
	return filepath.Join(dir, name+groups.SOPSPayloadSuffix)
}

// formatOf returns the payload format of a group.
func formatOf(group groups.Group) string {
	if group.Format == nil {
		return "sops"
	}
	return group.Format.Name()
}

// mustExist reports a readable file, or an error.
func mustExist(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s does not exist", path)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}
