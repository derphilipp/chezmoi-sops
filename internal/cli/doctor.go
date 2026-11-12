package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	sources := environment.sources()

	if jsonRequested(cmd) {
		output := jsonOutput{Command: "doctor", OK: true}
		for _, group := range environment.Layout.Groups {
			status := statusOfGroup(sources, group.Name)
			output.Groups = append(output.Groups, jsonGroup{
				Name:       group.Name,
				Format:     status.Format,
				Hosts:      group.Members,
				Recipients: group.Recipients,
			})
		}
		for _, host := range environment.Layout.Hosts {
			output.Hosts = append(output.Hosts, jsonHost{
				Host: host.Hostname(),
				Key:  strings.Join(host.Age, ", "),
			})
		}
		return printJSON(output)
	}

	fmt.Println()
	fmt.Println("chezmoi")
	fmt.Printf("  source directory: %s\n", environment.Config.SourceDir)
	fmt.Printf("  encryption:       %s\n", environment.Config.Encryption)
	if environment.Config.Identity == "" {
		fmt.Println("  identity:         none configured")
	} else {
		fmt.Printf("  identity:         %s\n", environment.Config.Identity)
	}

	fmt.Println()
	fmt.Println("Identity files")
	found := false
	for _, path := range identityPaths() {
		found = true
		fmt.Printf("  ✓ %s\n", path)
	}
	if !found {
		fmt.Println("  none found")
	}

	fmt.Println()
	fmt.Println("Secret groups")
	for _, group := range environment.Layout.Groups {
		status := statusOfGroup(sources, group.Name)
		mark := "✗"
		if status.Available {
			mark = "✓"
		}
		fmt.Printf("  %s %-14s %-6s %2d hosts  %s\n",
			mark, group.Name, status.Format, len(group.Members),
			strings.Join(group.Members, ", "))
		if !status.Available && status.Reason != "" {
			fmt.Printf("      %s\n", status.Reason)
		}
	}

	fmt.Println()
	fmt.Println("Machines")
	for _, host := range environment.Layout.Hosts {
		readable := environment.groupsOfHost(host.Name)
		fmt.Printf("  %-24s %s\n", host.Hostname(), strings.Join(readable, ", "))
	}
	fmt.Println()

	return nil
}

// identityPaths returns the identity files that are looked at, and exist.
func identityPaths() []string {
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

	seen := map[string]bool{}
	var found []string
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
