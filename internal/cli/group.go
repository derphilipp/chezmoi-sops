package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
	"github.com/spf13/cobra"
)

// newGroupCmd builds the command that manages the secret groups.
func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage the secret groups",
		Long: `Manage the secret groups.

A group is a set of machines plus the secrets they share. The machines that
may read a group are its members, and the payloads of the group are
encrypted for the age keys of its members.`,
	}

	cmd.AddCommand(
		newGroupListCmd(),
		newGroupCreateCmd(),
		newGroupEditCmd(),
		newGroupAddCmd(),
		newGroupRemoveCmd(),
		newGroupMembersCmd(),
		newGroupRenameCmd(),
		newGroupDeleteCmd(),
	)

	return cmd
}

func newGroupListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the groups, their members, and their state",
		Long: `Show the groups, their members, and their state.

The groups are listed in the order of the access file. That order decides
which value wins when two of them hold the same key.

A mark of "!" means that the payloads of the group are not encrypted for its
current members. Run "chezmoi sops sync" to encrypt them again.`,
		Args: cobra.NoArgs,
		RunE: runGroupList,
	}
	addJSONFlag(cmd)
	return cmd
}

func runGroupList(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	sources := environment.sources()

	if jsonRequested(cmd) {
		output := jsonOutput{Command: "group list", OK: true}
		for _, group := range environment.Layout.Groups {
			output.Groups = append(output.Groups, jsonGroup{
				Name:       group.Name,
				Format:     formatOfGroups(group, sources),
				Machines:   group.Members,
				Recipients: group.Recipients,
			})
		}
		return printJSON(cmd, output)
	}

	problems := environment.checkGroups()
	outOfSync := map[string]bool{}
	for _, problem := range problems {
		outOfSync[problem.Name] = true
	}

	cmd.Println()
	cmd.Println("Secret groups")
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
		cmd.Printf("  %s %-14s %-6s %2d machines  %s\n",
			mark, group.Name, formatOfGroups(group, sources), len(group.Members),
			strings.Join(group.Members, ", "))
	}

	if len(problems) > 0 {
		cmd.Println()
		cmd.Println("The payloads of these groups are not encrypted for the current members:")
		for _, problem := range problems {
			cmd.Printf("  %s: %s\n", problem.Name, problem.describe())
		}
		cmd.Println("Run 'chezmoi sops sync' to encrypt them again.")
	}
	cmd.Println()

	return nil
}

func newGroupCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name> [machine...]",
		Short: "Create a group",
		Long: `Create a group.

The group is added to the access file and gets a directory to hold its
payloads. The machines that may read it are given as arguments; they can be
changed later with "chezmoi sops group add" and "chezmoi sops group remove".

To give a machine secrets of its own, create a machine instead:
"chezmoi sops machine create <name> <age key>".`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completeNewGroup,
		RunE:              runGroupCreate,
	}
	addJSONFlag(cmd)
	return cmd
}

func runGroupCreate(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	name := args[0]
	members := args[1:]

	if _, ok := environment.Layout.Access.Group(name); ok {
		return fail("The group %q already exists.", name)
	}

	// The access file is written first: a directory without an entry in it
	// is a state the tool refuses to read.
	if err := environment.addGroup(name, members); err != nil {
		return fail("%s", err)
	}

	dir := filepath.Join(environment.secretsDir(), environment.secretsDirOf(kindGroup), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("Creating %s: %s", dir, err)
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: "group create",
			OK:      true,
			Message: fmt.Sprintf("Created the group %q.", name),
		})
	}

	cmd.Printf("Created the group %q: %s\n", name, dir)
	if len(members) == 0 {
		cmd.Println("Let machines read it with: chezmoi sops group add " + name + " <machine>")
	}
	return nil
}

func newGroupEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name> [file]",
		Short: "Decrypt a group, open it in the editor, and re-encrypt it",
		Long: `Decrypt a group, open it in the editor, and re-encrypt it.

The payload is decrypted with the identity of this machine. When the
machine cannot decrypt it, the payload is not overwritten unless --force is
given.

Without a file, every payload of the group is opened in one editor session.`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completeGroupTarget,
		RunE:              runGroupEdit,
	}
	cmd.Flags().BoolP("force", "f", false, "overwrite without decrypting first")
	cmd.Flags().Bool("sops", false, "convert the payload to the sops format")
	cmd.Flags().Bool("age", false, "convert the payload to the whole-file age format")
	addJSONFlag(cmd)
	return cmd
}

func runGroupEdit(cmd *cobra.Command, args []string) error {
	return editTarget(cmd, kindGroup, args[0], optionalFile(args))
}

func newGroupAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <group> <machine>...",
		Short: "Let machines read a group",
		Long: `Let machines read a group.

The machines are added to the members of the group. The payloads of the
group are encrypted again for their keys, so that they can read them.

The payloads can only be encrypted again by a machine that is able to read
them. Use --no-reencrypt to change the members without touching the
payloads.`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: completeGroupMachines,
		RunE:              runGroupAdd,
	}
	cmd.Flags().Bool("no-reencrypt", false, "do not encrypt the payloads of the group again")
	addJSONFlag(cmd)
	return cmd
}

func runGroupAdd(cmd *cobra.Command, args []string) error {
	name := args[0]
	machines := args[1:]

	environment, err := resolve()
	if err != nil {
		return err
	}

	group, ok := environment.Layout.Access.Group(name)
	if !ok {
		return fail("The group %q does not exist.", name)
	}

	for _, machine := range machines {
		if _, ok := environment.Layout.Access.Host(machine); !ok {
			return fail("The machine %q is not in %s.", machine, access.FileName)
		}
	}

	// The machines that are already members keep their place in the list.
	members := group.Members
	for _, machine := range machines {
		if !contains(members, machine) {
			members = append(members, machine)
		}
	}

	return setMembers(cmd, environment, "group add", name, members)
}

func newGroupRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <group> <machine>...",
		Short: "Stop machines from reading a group",
		Long: `Stop machines from reading a group.

The machines are removed from the members of the group, and the payloads of
the group are encrypted again for the keys of the remaining members, so that
the removed ones cannot read them any more.

The payloads can only be encrypted again by a machine that is able to read
them. Use --no-reencrypt to change the members without touching the
payloads.`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: completeGroupMachines,
		RunE:              runGroupRemove,
	}
	cmd.Flags().Bool("no-reencrypt", false, "do not encrypt the payloads of the group again")
	addJSONFlag(cmd)
	return cmd
}

func runGroupRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	machines := args[1:]

	environment, err := resolve()
	if err != nil {
		return err
	}

	group, ok := environment.Layout.Access.Group(name)
	if !ok {
		return fail("The group %q does not exist.", name)
	}

	for _, machine := range machines {
		if !contains(group.Members, machine) {
			return fail("The machine %q is not a member of the group %q.", machine, name)
		}
	}

	members := []string{}
	for _, member := range group.Members {
		if !contains(machines, member) {
			members = append(members, member)
		}
	}

	return setMembers(cmd, environment, "group remove", name, members)
}

func newGroupMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members <group>",
		Short: "Show the machines that may read a group",
		Long: `Show the machines that may read a group.

The members decide who may read the group: the recipients of its payloads
are the age keys of its members.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeGroups,
		RunE:              runGroupMembers,
	}
	addJSONFlag(cmd)
	return cmd
}

func runGroupMembers(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	name := args[0]

	group, ok := environment.Layout.Access.Group(name)
	if !ok {
		return fail("The group %q does not exist.", name)
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: "group members",
			OK:      true,
			Groups: []jsonGroup{{
				Name:       group.Name,
				Machines:   group.Members,
				Recipients: environment.recipientsOf(group.Name),
			}},
		})
	}

	cmd.Printf("%s\n", strings.Join(group.Members, ", "))
	return nil
}

func newGroupRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a group",
		Long: `Rename a group.

The entry in the access file and the directory are renamed together, so the
layout stays consistent. The payloads are not touched.`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeGroups,
		RunE:              runGroupRename,
	}
	addJSONFlag(cmd)
	return cmd
}

func runGroupRename(cmd *cobra.Command, args []string) error {
	return renameTarget(cmd, kindGroup, args[0], args[1])
}

func newGroupDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Remove a group and its payloads",
		Long: `Remove a group and its payloads.

The payload directory is removed and the entry is removed from the access
file.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeGroups,
		RunE:              runGroupDelete,
	}
	addJSONFlag(cmd)
	return cmd
}

func runGroupDelete(cmd *cobra.Command, args []string) error {
	return deleteTarget(cmd, kindGroup, args[0])
}

// setMembers writes the members of a group to the access file and encrypts
// its payloads again for them.
//
// The command is the name of the command that calls it, for the
// machine-readable output.
func setMembers(cmd *cobra.Command, environment *env, command, name string, members []string) error {
	noReencrypt, _ := cmd.Flags().GetBool("no-reencrypt")

	if err := environment.setMembers(name, members); err != nil {
		return fail("%s", err)
	}

	// The payloads are encrypted for the old members, so the new ones
	// cannot read them until they are encrypted again. The recipients come
	// from the file that was just written, not from the layout that was
	// read before the change.
	recipients, err := environment.newRecipients(name)
	if err != nil {
		return fail("%s", err)
	}

	reencrypted := false
	if !noReencrypt {
		reencrypted, err = environment.reencryptGroup(name, recipients)
		if err != nil {
			return fail("%s", err)
		}
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: command,
			OK:      true,
			Message: fmt.Sprintf("The group %q is now read by %s.", name, strings.Join(members, ", ")),
		})
	}

	cmd.Printf("The group %q is now read by %s.\n", name, strings.Join(members, ", "))
	switch {
	case reencrypted:
		cmd.Println("Its payloads were encrypted again for the new members.")
	case noReencrypt:
		cmd.Println("Its payloads were not encrypted again, so the new members cannot read them yet.")
	default:
		cmd.Println("Its payloads could not be encrypted again, so the new members cannot read them yet.")
		cmd.Println("Run 'chezmoi sops group edit " + name + "' to encrypt them again.")
	}
	return nil
}

// contains reports whether a list holds a value.
func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
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

// groupsOfMachine returns the groups a machine may read.
func (e *env) groupsOfMachine(name string) []string {
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

// recipientsOf returns the age public keys of a group.
func (e *env) recipientsOf(name string) []string {
	for _, group := range e.Layout.Groups {
		if group.Name == name {
			return group.Recipients
		}
	}
	return nil
}

// reencryptGroup encrypts the payloads of a group again, for its current
// members.
//
// It reports whether the payloads were encrypted: a group whose payloads
// cannot be decrypted - because this machine is not a recipient, or because
// there is no identity - cannot be encrypted again either.
func (e *env) reencryptGroup(name string, recipients []string) (bool, error) {
	var group groups.Group
	found := false
	for _, candidate := range e.Layout.Groups {
		if candidate.Name == name {
			group = candidate
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("the group %q does not exist", name)
	}

	files, err := groups.Payloads(group.Dir)
	if err != nil {
		return false, err
	}
	if len(files) == 0 {
		// A group without a payload has nothing to encrypt.
		return true, nil
	}

	if len(e.Identities) == 0 {
		return false, nil
	}

	for _, file := range files {
		values, err := e.decrypt([]string{file})
		if err != nil {
			return false, fmt.Errorf("the payload %s could not be decrypted, so it was not "+
				"encrypted again: %w", file, err)
		}

		encrypted, err := formatOf(file).Encrypt(ctx(), payload.Document(values), recipients)
		if err != nil {
			return false, fmt.Errorf("the payload %s could not be encrypted: %w", file, err)
		}
		if err := os.WriteFile(file, encrypted, 0o600); err != nil {
			return false, fmt.Errorf("writing %s: %w", file, err)
		}
	}

	return true, nil
}

// optionalFile returns the second argument, or an empty string when there
// is none.
func optionalFile(args []string) string {
	if len(args) < 2 {
		return ""
	}
	return args[1]
}
