package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/editor"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit [group]",
		Short: "Decrypt a group, open it in the editor, and re-encrypt it",
		Long: `Decrypt a group, open it in the editor, and re-encrypt it.

The group is decrypted with the identity of this machine. When the machine
cannot decrypt the group, the payload is not overwritten unless --force is
given.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runEdit,
	}
	cmd.Flags().BoolP("force", "f", false, "overwrite without decrypting first")
	cmd.Flags().Bool("sops", false, "convert the group to the sops format")
	cmd.Flags().Bool("age", false, "convert the group to the age format")
	return cmd
}

func runEdit(cmd *cobra.Command, args []string) error {
	name := "default"
	if len(args) == 1 {
		name = args[0]
	}

	force, _ := cmd.Flags().GetBool("force")
	wantSOPS, _ := cmd.Flags().GetBool("sops")
	wantAge, _ := cmd.Flags().GetBool("age")
	if wantSOPS && wantAge {
		return fail("Choose either --sops or --age, not both.")
	}

	environment, err := resolve()
	if err != nil {
		return err
	}

	group, found := environment.Registry.Get(name)
	if !found {
		// The group may exist with only a recipients file, which is a
		// group that has no payload yet.
		recipientsPath := groupRecipientsPath(environment, name)
		if err := mustExist(recipientsPath); err != nil {
			return fail("Group %q does not exist. Create it with: chezmoi sops new %s", name, name)
		}
		group = groups.Group{
			Name:           name,
			RecipientsPath: recipientsPath,
		}
	}

	format := "sops"
	switch {
	case wantAge:
		format = "age"
	case wantSOPS:
		format = "sops"
	case group.Format != nil:
		format = group.Format.Name()
	}

	var formatPayload payload.Payload
	if format == "age" {
		formatPayload = payload.NewAge()
	} else {
		formatPayload = payload.NewSOPS()
	}

	recipients, err := environment.recipientsFor(group)
	if err != nil {
		return fail("%s", err)
	}

	target := payloadPath(environment.Config.SecretsDir(), name, format)

	// The payload is read from the old file, so a conversion keeps the
	// values.
	source := target
	if group.PayloadPath != "" {
		source = group.PayloadPath
	}

	// The old payload may be in another format, so it is decrypted with
	// its own format and the new one is written in the wanted format.
	var sourceFormat payload.Payload = formatPayload
	if group.Format != nil {
		sourceFormat = group.Format
	}

	ed := editor.Editor{Command: flagEditor}
	result, err := ed.Edit(cmd.Context(), source, target, editor.Options{
		Format:       formatPayload,
		SourceFormat: sourceFormat,
		Recipients:   recipients,
		Identities:   environment.Identities,
		Force:        force,
		Template:     editor.DefaultTemplate,
	})
	if err != nil {
		return fail("%s", err)
	}

	switch {
	case result.Created:
		fmt.Printf("Created group %q in the %s format.\n", name, format)
	case result.Converted:
		fmt.Printf("Converted group %q to the %s format.\n", name, format)
	}

	if result.Empty {
		fmt.Println("The payload was empty, so an empty document was written instead.")
	}

	fmt.Printf("Encrypted group %q for:\n", name)
	for _, recipient := range recipients {
		fmt.Printf("    %s\n", recipient)
	}
	fmt.Println("Run 'chezmoi init' to load the secrets.")

	return nil
}

func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <name> [recipient ...]",
		Short: "Create a secret group",
		Long: `Create a secret group.

A group is a recipients file plus a payload. The recipients file lists the
age public keys that are allowed to decrypt the group. The payload starts
out empty and is filled in with "chezmoi sops edit".

With --per-host, one group is created per host, using the public keys of
that host from the recipient registry.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runNew,
	}
	cmd.Flags().Bool("per-host", false, "create one group per host")
	cmd.Flags().String("suffix", "", "suffix for the --per-host group names")
	cmd.Flags().Bool("sops", false, "use the sops format (default)")
	cmd.Flags().Bool("age", false, "use the whole-file age format")
	return cmd
}

func runNew(cmd *cobra.Command, args []string) error {
	perHost, _ := cmd.Flags().GetBool("per-host")
	suffix, _ := cmd.Flags().GetString("suffix")
	wantAge, _ := cmd.Flags().GetBool("age")

	format := "sops"
	if wantAge {
		format = "age"
	}

	environment, err := resolve()
	if err != nil {
		return err
	}

	if perHost {
		for _, host := range args {
			groupName := host
			if suffix != "" {
				groupName = host + "-" + suffix
			}

			keys, err := environment.hostKeys(host)
			if err != nil {
				return fail("%s", err)
			}
			if err := createGroup(environment, groupName, keys, format); err != nil {
				return err
			}
		}
		fmt.Println("Fill in the values with: chezmoi sops edit <group>")
		return nil
	}

	name := args[0]
	recipients := args[1:]

	if err := createGroup(environment, name, recipients, format); err != nil {
		return err
	}

	if len(recipients) == 0 {
		fmt.Printf("Add the recipients to %s, then run: chezmoi sops edit %s\n",
			groupRecipientsPath(environment, name), name)
		return nil
	}

	fmt.Printf("Fill in the values with: chezmoi sops edit %s\n", name)
	return nil
}

// createGroup creates the recipients file and an empty payload of a group.
func createGroup(environment *env, name string, recipients []string, format string) error {
	recipientsPath := groupRecipientsPath(environment, name)
	if err := mustExist(recipientsPath); err == nil {
		return fail("Group %q already exists: %s", name, recipientsPath)
	}

	var content strings.Builder
	fmt.Fprintf(&content, "# Recipients allowed to decrypt the %q secret group.\n", name)
	fmt.Fprintf(&content, "# Add one age public key (age1...) per line.\n")
	for _, recipient := range recipients {
		fmt.Fprintf(&content, "%s\n", recipient)
	}

	if err := os.WriteFile(recipientsPath, []byte(content.String()), 0o644); err != nil {
		return fail("Writing %s: %s", recipientsPath, err)
	}
	fmt.Printf("Created the recipients file: %s\n", recipientsPath)

	target := payloadPath(environment.Config.SecretsDir(), name, format)

	// The payload starts out empty. An empty document cannot be encrypted,
	// so a placeholder is written.
	var formatPayload payload.Payload
	if format == "age" {
		formatPayload = payload.NewAge()
	} else {
		formatPayload = payload.NewSOPS()
	}

	encrypted, err := formatPayload.Encrypt(cmdContext(), payload.Document{}, recipients)
	if err != nil {
		// The group is still created: the recipients file is what makes it
		// a group, and the payload can be filled in later.
		fmt.Fprintf(os.Stderr, "Note: the empty payload could not be created yet: %s\n", err)
		fmt.Printf("Add the recipients, then run: chezmoi sops edit %s\n", name)
		return nil
	}

	if err := os.WriteFile(target, encrypted, 0o600); err != nil {
		return fail("Writing %s: %s", target, err)
	}
	fmt.Printf("Created the payload: %s\n", target)

	return nil
}

func newGroupsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "groups",
		Short: "Show which machines are in which group",
		Long: `Show which machines are in which group.

The first table lists the groups and the machines that can read them. The
second table lists the machines and the groups they can read.`,
		Args: cobra.NoArgs,
		RunE: runGroups,
	}
}

func runGroups(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	registry, err := environment.hostRegistry()
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Secret groups")
	for _, group := range environment.Registry.Groups {
		hosts := environment.hostsOfGroup(group, registry)
		noun := "machines"
		if len(hosts) == 1 {
			noun = "machine "
		}
		fmt.Printf("  %-14s %2d %-9s %s\n", group.Name, len(hosts), noun, strings.Join(hosts, ", "))
	}

	fmt.Println()
	fmt.Println("Who can read what")
	for _, entry := range registry.Entries() {
		groupsOf := environment.groupsOfKey(entry.Key)
		short := entry.Key
		if len(short) > 10 {
			short = short[:10] + "…"
		}
		fmt.Printf("  %-34s %-12s %s\n", entry.Host, short, strings.Join(groupsOf, ", "))
	}

	return nil
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <group>",
		Short: "Remove a secret group",
		Long: `Remove a secret group.

The recipients file and the payload of the group are removed. The recipient
registry, which is the "default" group, cannot be removed.`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
}

func runDelete(cmd *cobra.Command, args []string) error {
	name := args[0]

	if name == "default" {
		return fail("The group %q is the recipient registry and cannot be deleted.", name)
	}

	environment, err := resolve()
	if err != nil {
		return err
	}

	dir := environment.Config.SecretsDir()
	removed := 0
	for _, suffix := range []string{
		groups.RecipientsSuffix,
		groups.SOPSPayloadSuffix,
		groups.AgePayloadSuffix,
	} {
		path := dir + string(os.PathSeparator) + name + suffix
		if err := os.Remove(path); err == nil {
			removed++
			fmt.Printf("Removed %s\n", path)
		} else if !os.IsNotExist(err) {
			return fail("Removing %s: %s", path, err)
		}
	}

	if removed == 0 {
		return fail("Group %q does not exist.", name)
	}

	fmt.Println("Run 'chezmoi init && chezmoi apply' to apply the change.")
	return nil
}

// groupRecipientsPath returns the path of the recipients file of a group.
func groupRecipientsPath(environment *env, name string) string {
	return environment.Config.SecretsDir() + string(os.PathSeparator) + name + groups.RecipientsSuffix
}

// hostsOfGroup returns the host names that can read a group.
func (e *env) hostsOfGroup(group groups.Group, registry groups.HostRegistry) []string {
	recipients, err := group.Recipients()
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var hosts []string
	for _, recipient := range recipients {
		for _, host := range registry.HostsForKey(recipient) {
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}

// groupsOfKey returns the groups a public key can read.
func (e *env) groupsOfKey(key string) []string {
	var names []string
	for _, group := range e.Registry.Groups {
		recipients, err := group.Recipients()
		if err != nil {
			continue
		}
		for _, recipient := range recipients {
			if recipient == key {
				names = append(names, group.Name)
				break
			}
		}
	}
	return names
}
