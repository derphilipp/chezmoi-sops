package cli

import (
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
				Machines:   group.Members,
				Recipients: group.Recipients,
			})
		}
		for _, machine := range environment.Layout.Machines {
			output.Machines = append(output.Machines, jsonMachine{
				Machine: machine.Hostname(),
				Key:     strings.Join(machine.Age, ", "),
			})
		}
		return printJSON(cmd, output)
	}

	cmd.Println()
	cmd.Println("chezmoi")
	cmd.Printf("  source directory: %s\n", environment.Config.SourceDir)
	cmd.Printf("  encryption:       %s\n", environment.Config.Encryption)
	if environment.Config.Identity == "" {
		cmd.Println("  identity:         none configured")
	} else {
		cmd.Printf("  identity:         %s\n", environment.Config.Identity)
	}

	cmd.Println()
	cmd.Println("Identity files")
	found := false
	for _, path := range identityPaths() {
		found = true
		cmd.Printf("  ✓ %s\n", path)
	}
	if !found {
		cmd.Println("  none found")
	}

	problems := environment.checkGroups()
	outOfSync := map[string]outOfSync{}
	for _, problem := range problems {
		outOfSync[problem.Name] = problem
	}

	cmd.Println()
	cmd.Println("Secret groups")
	for _, group := range environment.Layout.Groups {
		status := statusOfGroup(sources, group.Name)
		mark := "✗"
		if status.Available {
			mark = "✓"
		}
		cmd.Printf("  %s %-14s %-6s %2d machines  %s\n",
			mark, group.Name, status.Format, len(group.Members),
			strings.Join(group.Members, ", "))
		if !status.Available && status.Reason != "" {
			cmd.Printf("      %s\n", status.Reason)
		}
		if problem, ok := outOfSync[group.Name]; ok {
			cmd.Printf("      the payload is out of date: %s\n", problem.describe())
			cmd.Printf("      run 'chezmoi sops sync' to encrypt it again\n")
		}
	}

	cmd.Println()
	cmd.Println("Machines")
	for _, machine := range environment.Layout.Machines {
		readable := environment.groupsOfMachine(machine.Name)
		cmd.Printf("  %-24s %s\n", machine.Hostname(), strings.Join(readable, ", "))
	}
	cmd.Println()

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
