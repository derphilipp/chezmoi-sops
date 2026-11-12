package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/editor"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <group|host>/<name>[/<file>]",
		Short: "Decrypt a group or a host, open it in the editor, and re-encrypt it",
		Long: `Decrypt a group or a host, open it in the editor, and re-encrypt it.

The payload is decrypted with the identity of this machine. When the
machine cannot decrypt it, the payload is not overwritten unless --force is
given.

Without a file, every payload of the group or host is opened in one editor
session.`,
		Args: cobra.ExactArgs(1),
		RunE: runEdit,
	}
	cmd.Flags().BoolP("force", "f", false, "overwrite without decrypting first")
	cmd.Flags().Bool("sops", false, "convert the payload to the sops format")
	cmd.Flags().Bool("age", false, "convert the payload to the whole-file age format")
	addJSONFlag(cmd)
	return cmd
}

func runEdit(cmd *cobra.Command, args []string) error {
	target, err := parseTarget(args[0])
	if err != nil {
		return fail("%s", err)
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

	dir, recipients, err := environment.targetDir(target)
	if err != nil {
		return fail("%s", err)
	}

	// A group or a machine may have no payloads yet. Its directory is
	// created here, so the first payload has a place to go.
	if dir == "" {
		dir = filepath.Join(environment.secretsDir(), target.Kind+"s", target.Name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fail("Creating %s: %s", dir, err)
		}
	}

	files, err := groups.Payloads(dir)
	if err != nil {
		return fail("%s", err)
	}
	if target.File != "" {
		files = []string{filepath.Join(dir, target.File)}
	}

	if len(files) == 0 {
		// A group without a payload is a group that has just been
		// created: the first payload is created here.
		files = []string{filepath.Join(dir, target.Name+".sops.yaml")}
	}

	for _, file := range files {
		format := groups.FormatOf(file)
		if wantSOPS {
			format = "sops"
		}
		if wantAge {
			format = "age"
		}

		newFile := file
		if format != groups.FormatOf(file) {
			newFile = replaceFormat(file, format)
		}

		if err := environment.editFile(newFile, file, format, recipients, force, flagEditor); err != nil {
			return fail("%s", err)
		}
	}

	return nil
}

// target is a group or a host, and optionally a file inside it.
type target struct {
	// Kind is "group" or "host".
	Kind string

	// Name is the name of the group or the host.
	Name string

	// File is the payload file inside it. It is empty when the whole
	// group or host is edited.
	File string
}

// String returns the target as it was written.
func (t target) String() string {
	if t.File == "" {
		return t.Kind + "/" + t.Name
	}
	return t.Kind + "/" + t.Name + "/" + t.File
}

// parseTarget parses a "group/name", "host/name" or "group/name/file"
// argument.
func parseTarget(arg string) (target, error) {
	parts := strings.Split(arg, "/")

	switch len(parts) {
	case 2:
		if parts[0] != groups.KindGroup && parts[0] != groups.KindHost {
			return target{}, fmt.Errorf("Unknown kind %q: use %q or %q.",
				parts[0], groups.KindGroup, groups.KindHost)
		}
		return target{Kind: parts[0], Name: parts[1]}, nil
	case 3:
		if parts[0] != groups.KindGroup && parts[0] != groups.KindHost {
			return target{}, fmt.Errorf("Unknown kind %q: use %q or %q.",
				parts[0], groups.KindGroup, groups.KindHost)
		}
		return target{Kind: parts[0], Name: parts[1], File: parts[2]}, nil
	default:
		return target{}, fmt.Errorf("Expected <%s|name>[/<file>], got %q.",
			groups.KindGroup+"/"+groups.KindHost, arg)
	}
}

// targetDir returns the directory of a group or a host, and the recipients
// its payloads are encrypted for.
func (e *env) targetDir(t target) (string, []string, error) {
	switch t.Kind {
	case groups.KindGroup:
		for _, group := range e.Layout.Groups {
			if group.Name == t.Name {
				return group.Dir, group.Recipients, nil
			}
		}
		return "", nil, fmt.Errorf("The group %q does not exist.", t.Name)
	case groups.KindHost:
		for _, host := range e.Layout.Hosts {
			if host.Name == t.Name {
				return host.Dir, host.Age, nil
			}
		}
		return "", nil, fmt.Errorf("The host %q does not exist.", t.Name)
	default:
		return "", nil, fmt.Errorf("Unknown kind %q.", t.Kind)
	}
}

// editFile decrypts a payload file, opens it in the editor and encrypts it
// again.
func (e *env) editFile(path, sourcePath, format string, recipients []string, force bool, editorCommand string) error {
	var formatPayload payload.Payload
	if format == "age" {
		formatPayload = payload.NewAge()
	} else {
		formatPayload = payload.NewSOPS()
	}

	var sourceFormat payload.Payload = formatPayload
	if sourcePath != path {
		sourceFormat = formatOf(sourcePath)
	}

	ed := editor.Editor{Command: editorCommand}
	_, err := ed.Edit(ctx(), sourcePath, path, editor.Options{
		Format:       formatPayload,
		SourceFormat: sourceFormat,
		Recipients:   recipients,
		Identities:   e.Identities,
		Force:        force,
		Template:     editor.DefaultTemplate,
	})
	if err != nil {
		return err
	}

	// Converting the format leaves the old file behind.
	if sourcePath != path {
		if err := os.Remove(sourcePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing the old payload %s: %w", sourcePath, err)
		}
	}

	return nil
}

// replaceFormat returns the name of a payload file in another format.
func replaceFormat(path, format string) string {
	base := strings.TrimSuffix(path, ".sops.yaml")
	base = strings.TrimSuffix(base, ".age")
	if format == "age" {
		return base + ".age"
	}
	return base + ".sops.yaml"
}

func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <group> [host ...]",
		Short: "Create a secret group",
		Long: `Create a secret group.

The group is added to the access file and gets a directory to hold its
payloads. Add the hosts that may read it with "chezmoi sops members".

To give a machine its own secrets, create a host directory instead:
"chezmoi sops new --host <host>".`,
		Args: cobra.MinimumNArgs(1),
		RunE: runNew,
	}
	cmd.Flags().Bool("host", false, "create the private directory of a host instead of a group")
	addJSONFlag(cmd)
	return cmd
}

func runNew(cmd *cobra.Command, args []string) error {
	isHost, _ := cmd.Flags().GetBool("host")

	environment, err := resolve()
	if err != nil {
		return err
	}

	name := args[0]
	members := args[1:]

	if isHost {
		// The machine needs its keys: without them it could not read
		// anything.
		keys := members
		if len(keys) == 0 {
			return fail("A machine needs at least one age key: chezmoi sops new --host %s age1...", name)
		}
		if _, ok := environment.Layout.Access.Host(name); ok {
			return fail("The host %q already exists.", name)
		}

		// The access file is written first: a directory without an entry
		// in it is a state the tool refuses to read.
		if err := environment.addHost(name, keys); err != nil {
			return fail("%s", err)
		}

		dir := filepath.Join(environment.secretsDir(), groups.HostsDir, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fail("Creating %s: %s", dir, err)
		}
		if !jsonRequested(cmd) {
			fmt.Printf("Created the host %q: %s\n", name, dir)
		}
		return nil
	}

	if _, ok := environment.Layout.Access.Group(name); ok {
		return fail("The group %q already exists.", name)
	}

	// The access file is written first, for the same reason.
	if err := environment.addGroup(name, members); err != nil {
		return fail("%s", err)
	}

	dir := filepath.Join(environment.secretsDir(), groups.GroupsDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("Creating %s: %s", dir, err)
	}

	if !jsonRequested(cmd) {
		fmt.Printf("Created the group %q: %s\n", name, dir)
		if len(members) == 0 {
			fmt.Printf("Add the hosts that may read it with: chezmoi sops members %s\n", name)
		}
	}

	return nil
}

func newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "Show the groups, the hosts, and who can read what",
		Long: `Show the groups, the hosts, and who can read what.

The groups are listed in the order of the access file. That order decides
which value wins when two of them hold the same key.`,
		Args: cobra.NoArgs,
		RunE: runGroups,
	}
	addJSONFlag(cmd)
	return cmd
}

func runGroups(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	sources := environment.sources()

	if jsonRequested(cmd) {
		output := jsonOutput{Command: "groups", OK: true}
		for _, group := range environment.Layout.Groups {
			output.Groups = append(output.Groups, jsonGroup{
				Name:       group.Name,
				Format:     formatOfGroups(group, sources),
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

	problems := environment.checkGroups()
	outOfSync := map[string]bool{}
	for _, problem := range problems {
		outOfSync[problem.Name] = true
	}

	fmt.Println()
	fmt.Println("Secret groups")
	for _, group := range environment.Layout.Groups {
		status := statusOfGroup(sources, group.Name)
		mark := "✗"
		if status.Available {
			mark = "✓"
		}
		if outOfSync[group.Name] {
			// The payload is encrypted for a different set of keys than
			// the group has members.
			mark = "!"
		}
		fmt.Printf("  %s %-14s %-6s %2d hosts  %s\n",
			mark, group.Name, formatOfGroups(group, sources), len(group.Members),
			strings.Join(group.Members, ", "))
	}

	if len(problems) > 0 {
		fmt.Println()
		fmt.Println("The payloads of these groups are not encrypted for the current members:")
		for _, problem := range problems {
			fmt.Printf("  %s: %s\n", problem.Name, problem.describe())
		}
		fmt.Println("Run 'chezmoi sops sync' to encrypt them again.")
	}

	fmt.Println()
	fmt.Println("Machines")
	for _, host := range environment.Layout.Hosts {
		groups := environment.groupsOfHost(host.Name)
		fmt.Printf("  %-24s %s\n", host.Hostname(), strings.Join(groups, ", "))
	}
	fmt.Println()

	return nil
}

// formatOfGroups returns the payload format of a group.
func formatOfGroups(group groups.Group, sources []groups.Source) string {
	for _, source := range sources {
		if source.Kind == groups.KindGroup && source.Name == group.Name {
			return source.Format
		}
	}
	return "sops"
}

// statusOfGroup returns the status of a group.
func statusOfGroup(sources []groups.Source, name string) groups.Status {
	for _, source := range sources {
		if source.Kind == groups.KindGroup && source.Name == name {
			return groups.Status{
				Kind:      source.Kind,
				Name:      source.Name,
				Available: source.Available,
				Reason:    source.Reason,
				Format:    source.Format,
				Payloads:  source.Files,
			}
		}
	}
	return groups.Status{Kind: groups.KindGroup, Name: name}
}

// groupsOfHost returns the groups a host may read.
func (e *env) groupsOfHost(name string) []string {
	var names []string
	for _, group := range e.Layout.Groups {
		for _, member := range group.Members {
			if member == name {
				names = append(names, group.Name)
				break
			}
		}
	}
	return names
}

func newDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <group|host>/<name>",
		Short: "Remove a secret group or a host",
		Long: `Remove a secret group or a host.

The payload directory is removed and the entry is removed from the access
file.`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
	addJSONFlag(cmd)
	return cmd
}

func runDelete(cmd *cobra.Command, args []string) error {
	t, err := parseTarget(args[0])
	if err != nil {
		return fail("%s", err)
	}

	environment, err := resolve()
	if err != nil {
		return err
	}

	dir, _, err := environment.targetDir(t)
	if err != nil {
		return fail("%s", err)
	}

	removed := []string{}
	if dir != "" {
		files, err := groups.Payloads(dir)
		if err != nil {
			return fail("%s", err)
		}
		for _, file := range files {
			if err := os.Remove(file); err == nil {
				removed = append(removed, file)
			}
		}
		if err := os.Remove(dir); err == nil {
			removed = append(removed, dir)
		}
	}

	if err := environment.removeEntry(t); err != nil {
		return fail("%s", err)
	}

	if jsonRequested(cmd) {
		return printJSON(jsonOutput{
			Command: "delete",
			OK:      true,
			Message: fmt.Sprintf("Deleted %s.", t),
			Removed: removed,
		})
	}

	for _, path := range removed {
		fmt.Printf("Removed %s\n", path)
	}
	fmt.Println("Run 'chezmoi init && chezmoi apply' to apply the change.")
	return nil
}
