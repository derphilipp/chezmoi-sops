// Package chezmoi reads the configuration of the chezmoi installation the
// tool works with.
//
// The tool has no configuration of its own: chezmoi's config is the single
// source of truth for the identity and the default recipients.
package chezmoi

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Config is what the tool needs to know about the chezmoi installation.
type Config struct {
	// SourceDir is the chezmoi source directory.
	SourceDir string

	// Identity is the age identity chezmoi is configured with.
	Identity string

	// RecipientsFile is the age recipients file chezmoi is configured with.
	RecipientsFile string

	// Encryption is the encryption scheme chezmoi is configured with.
	Encryption string
}

// SecretsDir is the directory the secret groups live in.
func (c Config) SecretsDir() string {
	return joinPath(c.SourceDir, ".secrets")
}

// Load reads the chezmoi configuration.
//
// The source directory is taken from sourceDir when it is given. Otherwise
// it comes from chezmoi:
//
//   - $CHEZMOI_SOURCE_DIR, which chezmoi sets before it runs a template or
//     a plugin, so a plugin sees the source directory of the chezmoi
//     invocation it belongs to;
//   - "chezmoi source-path", which works even when there is no
//     configuration file at all, which matters on a machine that has not
//     been initialised yet.
//
// The rest of the configuration comes from "chezmoi data --format json". It
// reads the *rendered* configuration file, not the template, so calling it
// from a template does not recurse. It is a bonus: without chezmoi, or
// without a configuration file, the tool still works and finds the identity
// itself.
func Load(sourceDir string) (Config, error) {
	config := Config{}

	dir := strings.TrimSpace(sourceDir)
	if dir == "" {
		var err error
		dir, err = sourcePath()
		if err != nil {
			return config, err
		}
	}
	config.SourceDir = dir

	if data, err := data(dir); err == nil {
		config.Identity = data.Chezmoi.Config.Age.Identity
		config.RecipientsFile = data.Chezmoi.Config.Age.RecipientsFile
		config.Encryption = data.Chezmoi.Config.Encryption
	}

	return config, nil
}

// sourcePath returns the chezmoi source directory.
func sourcePath() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("CHEZMOI_SOURCE_DIR")); dir != "" {
		return dir, nil
	}

	out, err := exec.Command("chezmoi", "source-path").Output()
	if err != nil {
		return "", fmt.Errorf("reading the chezmoi source directory: %w "+
			"(is chezmoi installed, or was --source-dir given?)", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("chezmoi did not report a source directory")
	}
	return dir, nil
}

// chezmoiData is the part of "chezmoi data --format json" the tool needs.
type chezmoiData struct {
	Chezmoi struct {
		SourceDir string `json:"sourceDir"`
		Config    struct {
			Encryption string `json:"encryption"`
			Age        struct {
				Identity       string `json:"identity"`
				RecipientsFile string `json:"recipientsFile"`
			} `json:"age"`
		} `json:"config"`
	} `json:"chezmoi"`
}

// data returns the effective chezmoi configuration.
//
// The configuration of the chezmoi invocation the tool belongs to is read,
// not the default one: chezmoi sets $CHEZMOI_CONFIG_FILE and
// $CHEZMOI_SOURCE_DIR before it runs a template or a plugin, and a plugin
// that read the default configuration would get the wrong identity.
func data(sourceDir string) (chezmoiData, error) {
	var parsed chezmoiData

	var args []string
	if configFile := strings.TrimSpace(os.Getenv("CHEZMOI_CONFIG_FILE")); configFile != "" {
		args = append(args, "--config", configFile)
	}
	if dir := strings.TrimSpace(os.Getenv("CHEZMOI_SOURCE_DIR")); dir != "" {
		args = append(args, "--source", dir)
	} else if sourceDir != "" {
		args = append(args, "--source", sourceDir)
	}
	args = append(args, "data", "--format", "json")

	out, err := exec.Command("chezmoi", args...).Output()
	if err != nil {
		return parsed, fmt.Errorf("reading the chezmoi configuration: %w", err)
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return parsed, fmt.Errorf("parsing the chezmoi configuration: %w", err)
	}
	return parsed, nil
}

// joinPath joins path elements with the platform separator.
func joinPath(elems ...string) string {
	return strings.Join(elems, string(os.PathSeparator))
}
