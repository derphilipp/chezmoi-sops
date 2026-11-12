package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/chezmoi"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/spf13/cobra"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Convert the old layout to the access file layout",
		Long: `Convert the old layout to the access file layout.

The old layout had a recipients file per group, and the "default" group
doubled as the recipient registry. The new layout has one access file that
lists the machines and the groups, and the recipients of a group are
derived from its members.

The payloads are moved, not rewritten: the encrypted files are the same
bytes afterwards.`,
		Args: cobra.NoArgs,
		RunE: runMigrate,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMigrate(cmd *cobra.Command, args []string) error {
	// The migration runs on the old layout, so it cannot use resolve():
	// that needs the access file, which is what the migration creates.
	config, err := chezmoi.Load()
	if err != nil {
		return err
	}
	if flagSourceDir != "" {
		config.SourceDir = flagSourceDir
	}

	dir := config.SecretsDir()

	// The old layout: <group>.recipients.txt next to <group>.sops.yaml.
	old, err := readOldLayout(dir)
	if err != nil {
		return fail("%s", err)
	}
	if len(old) == 0 {
		return fail("There is nothing to migrate: no group files were found in %s.", dir)
	}

	// The hosts come from the registry: the "default" group, whose
	// recipients file names the machine each key belongs to.
	registry, err := readOldRegistry(filepath.Join(dir, "default.recipients.txt"))
	if err != nil {
		return fail("%s", err)
	}

	// Build the access file.
	file := &access.File{Path: filepath.Join(dir, access.FileName)}
	for _, name := range sortedKeys(registry) {
		file.Hosts = append(file.Hosts, access.Host{
			Name: name,
			Age:  registry[name],
		})
	}
	for _, group := range old {
		file.Groups = append(file.Groups, access.Group{
			Name:    migratedName(group.Name),
			Members: hostsOfGroup(group, registry),
		})
	}

	// Write the access file.
	if err := writeAccess(file.Path, file); err != nil {
		return fail("Writing %s: %s", file.Path, err)
	}

	// Move the payloads.
	for _, group := range old {
		if group.Payload == "" {
			continue
		}
		// The directory already says which group the payload belongs to,
		// so the file is named after the group too.
		target := filepath.Join(dir, groups.GroupsDir, migratedName(group.Name), migratedName(group.Name)+payloadSuffix(group.Payload))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fail("Creating %s: %s", filepath.Dir(target), err)
		}
		if err := os.Rename(group.Payload, target); err != nil {
			return fail("Moving %s to %s: %s", group.Payload, target, err)
		}
	}

	// Remove the old recipients files.
	for _, group := range old {
		path := filepath.Join(dir, group.Name+".recipients.txt")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fail("Removing %s: %s", path, err)
		}
	}

	if jsonRequested(cmd) {
		return printJSON(jsonOutput{
			Command: "migrate",
			OK:      true,
			Message: fmt.Sprintf("Migrated %d groups to %s.", len(old), access.FileName),
		})
	}

	fmt.Printf("Wrote %s\n", file.Path)
	for _, group := range old {
		fmt.Printf("Moved the group %q\n", group.Name)
	}
	fmt.Println("Run 'chezmoi init && chezmoi apply' to apply the change.")
	return nil
}

// sharedGroupName is the name of the group that holds the secrets every
// machine is meant to have.
//
// The old layout called it "default", but that name was doing two jobs: it
// was the recipient registry as well as a group. In the new layout the
// registry is the hosts section of the access file, so the group can have
// a name that says what it is.
//
// It also sorts before the other groups, which keeps the merge order the
// same: the shared secrets win over the more specific ones.
const sharedGroupName = "common"

// migratedName returns the name a group gets in the new layout.
func migratedName(name string) string {
	if name == "default" {
		return sharedGroupName
	}
	return name
}

// oldGroup is a group of the old layout.
type oldGroup struct {
	// Name is the name of the group.
	Name string

	// Recipients is the path of the recipients file.
	Recipients string

	// Payload is the path of the encrypted payload.
	Payload string
}

// readOldLayout reads the groups of the old layout.
func readOldLayout(dir string) ([]oldGroup, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var found []oldGroup
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".recipients.txt") {
			continue
		}

		group := oldGroup{
			Name:       strings.TrimSuffix(name, ".recipients.txt"),
			Recipients: filepath.Join(dir, name),
		}
		for _, suffix := range []string{".sops.yaml", ".yaml.age"} {
			payload := filepath.Join(dir, group.Name+suffix)
			if _, err := os.Stat(payload); err == nil {
				group.Payload = payload
				break
			}
		}
		found = append(found, group)
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found, nil
}

// readOldRegistry reads the recipient registry: the machine names and their
// keys.
func readOldRegistry(path string) (map[string][]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"the recipient registry %s is missing, so the machines cannot be determined", path)
		}
		return nil, err
	}

	registry := map[string][]string{}
	host := ""

	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "#"):
			host = strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		default:
			if host == "" {
				continue
			}
			registry[host] = append(registry[host], trimmed)
		}
	}

	return registry, nil
}

// hostsOfGroup returns the machines whose keys are in a group.
func hostsOfGroup(group oldGroup, registry map[string][]string) []string {
	content, err := os.ReadFile(group.Recipients)
	if err != nil {
		return nil
	}

	var hosts []string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for host, keys := range registry {
			for _, key := range keys {
				if key == trimmed {
					hosts = append(hosts, host)
				}
			}
		}
	}

	sort.Strings(hosts)
	return hosts
}

// payloadSuffix returns the format suffix of a payload file.
func payloadSuffix(path string) string {
	if strings.HasSuffix(path, ".sops.yaml") {
		return ".sops.yaml"
	}
	return ".age"
}

// sortedKeys returns the keys of a map in sorted order.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
