package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the setup and report what works and what does not",
		Long: `Check the setup and report what works and what does not.

The report covers the chezmoi installation, the identity that would be
used, and every group: whether it can be decrypted, and why not when it
cannot.`,
		Args: cobra.NoArgs,
		RunE: runDoctor,
	}
	addJSONFlag(cmd)
	return cmd
}

func runDoctor(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	report := doctorReport{
		Config: doctorConfig{
			SourceDir:  environment.Config.SourceDir,
			Identity:   environment.Config.Identity,
			Encryption: environment.Config.Encryption,
		},
	}
	report.Identities = identityPaths()

	for _, group := range environment.Registry.Groups {
		entry := doctorGroup{
			Name:           group.Name,
			Format:         formatOf(group),
			RecipientsFile: group.RecipientsPath,
			Payload:        group.PayloadPath,
		}

		recipients, err := group.Recipients()
		if err != nil {
			entry.Problem = fmt.Sprintf("the recipients file cannot be read: %s", err)
		} else {
			entry.Recipients = recipients
		}

		raw, err := os.ReadFile(group.PayloadPath)
		switch {
		case err != nil:
			entry.Problem = "the payload is missing"
		case len(environment.Identities) == 0:
			entry.Problem = "no identity was found, so nothing can be decrypted"
		default:
			if _, err := group.Format.Decrypt(cmdContext(), raw, environment.Identities); err != nil {
				entry.Problem = "the payload cannot be decrypted with the local identity"
			} else {
				entry.Decryptable = true
			}
		}

		report.Groups = append(report.Groups, entry)
	}

	if jsonRequested(cmd) {
		return printJSONDoctor(report)
	}

	printDoctor(report)
	return nil
}

// doctorReport is the machine-readable report of the doctor command.
type doctorReport struct {
	// Config is the chezmoi configuration.
	Config doctorConfig `json:"config"`

	// Identities are the identity files that were looked at.
	Identities []string `json:"identities"`

	// Groups are the groups that were found.
	Groups []doctorGroup `json:"groups"`
}

// doctorConfig is the chezmoi part of the report.
type doctorConfig struct {
	// SourceDir is the chezmoi source directory.
	SourceDir string `json:"sourceDir"`

	// Identity is the identity chezmoi is configured with.
	Identity string `json:"identity"`

	// Encryption is the encryption scheme chezmoi is configured with.
	Encryption string `json:"encryption"`
}

// doctorGroup is one group in the report.
type doctorGroup struct {
	// Name is the name of the group.
	Name string `json:"name"`

	// Format is the payload format of the group.
	Format string `json:"format"`

	// RecipientsFile is the path of the recipients file.
	RecipientsFile string `json:"recipientsFile"`

	// Payload is the path of the encrypted payload.
	Payload string `json:"payload"`

	// Recipients are the age public keys of the group.
	Recipients []string `json:"recipients"`

	// Decryptable is true when the group can be decrypted.
	Decryptable bool `json:"decryptable"`

	// Problem explains why the group cannot be decrypted.
	Problem string `json:"problem,omitempty"`
}

// printJSONDoctor writes the machine-readable report.
func printJSONDoctor(report doctorReport) error {
	output := jsonOutput{Command: "doctor", OK: true}
	for _, group := range report.Groups {
		output.Groups = append(output.Groups, jsonGroup{
			Name:           group.Name,
			Format:         group.Format,
			RecipientsFile: group.RecipientsFile,
			Payload:        group.Payload,
			Recipients:     group.Recipients,
		})
	}
	return printJSON(output)
}

// printDoctor writes the human-readable report.
func printDoctor(report doctorReport) {
	fmt.Println()
	fmt.Println("chezmoi")
	fmt.Printf("  source directory: %s\n", report.Config.SourceDir)
	fmt.Printf("  encryption:       %s\n", report.Config.Encryption)
	if report.Config.Identity == "" {
		fmt.Println("  identity:         none configured")
	} else {
		fmt.Printf("  identity:         %s\n", report.Config.Identity)
	}

	fmt.Println()
	fmt.Println("Identity files")
	if len(report.Identities) == 0 {
		fmt.Println("  none found")
	}
	for _, path := range report.Identities {
		mark := " "
		if _, err := os.Stat(path); err == nil {
			mark = "✓"
		}
		fmt.Printf("  %s %s\n", mark, path)
	}

	fmt.Println()
	fmt.Println("Secret groups")
	if len(report.Groups) == 0 {
		fmt.Println("  none found")
	}
	for _, group := range report.Groups {
		mark := "✗"
		if group.Decryptable {
			mark = "✓"
		}
		fmt.Printf("  %s %-14s %-6s %d recipients", mark, group.Name, group.Format, len(group.Recipients))
		if group.Problem != "" {
			fmt.Printf("  (%s)", group.Problem)
		}
		fmt.Println()
	}
	fmt.Println()
}

// identityPaths returns the identity files that are looked at, and whether
// they exist.
func identityPaths() []string {
	paths := identityCandidates()
	found := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

// identityCandidates returns the identity files that are looked at.
func identityCandidates() []string {
	var paths []string
	if flagIdentity != "" {
		paths = append(paths, flagIdentity)
	}
	if env := os.Getenv("SOPS_AGE_KEY_FILE"); env != "" {
		paths = append(paths, env)
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".chezmoi-age-identity.txt"),
			filepath.Join(home, ".age", "key.txt"),
			filepath.Join(home, ".config", "sops", "age", "keys.txt"),
		)
	}
	if appData := os.Getenv("AppData"); appData != "" {
		paths = append(paths, filepath.Join(appData, "sops", "age", "keys.txt"))
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "sops", "age", "keys.txt"))
	}
	return paths
}
