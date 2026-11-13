package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
	"github.com/spf13/cobra"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys [machine] [agekey ...]",
		Short: "Show or set the age keys of a machine",
		Long: `Show or set the age keys of a machine.

Without a machine, the keys of every machine are listed. With a machine but
without a key, the keys of that machine are listed. With keys, they are
replaced.

A machine may have more than one key, for example one for the native
system and one for a virtual machine.

Changing the keys does not re-encrypt the payloads of the groups the
machine is in. Run "chezmoi sops sync" afterwards, or edit the groups
by hand.`,
		Args: cobra.ArbitraryArgs,
		RunE: runKeys,
	}
	addJSONFlag(cmd)
	return cmd
}

func runKeys(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	// Without a machine, every machine is listed.
	if len(args) == 0 {
		return runHosts(cmd, args)
	}

	name := args[0]
	keys := args[1:]

	host, ok := environment.Layout.Access.Host(name)
	if !ok {
		return fail("The host %q does not exist.", name)
	}

	if len(keys) == 0 {
		if jsonRequested(cmd) {
			return printJSON(cmd, jsonOutput{
				Command: "keys",
				OK:      true,
				Hosts: []jsonHost{{
					Host:   host.Hostname(),
					Key:    strings.Join(host.Age, ", "),
					Groups: environment.groupsOfHost(name),
				}},
			})
		}
		cmd.Printf("%s\n", host.Hostname())
		for _, key := range host.Age {
			cmd.Printf("    %s\n", key)
		}
		return nil
	}

	if err := environment.setHostKeys(name, keys); err != nil {
		return fail("%s", err)
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: "keys",
			OK:      true,
			Message: fmt.Sprintf("The machine %q has %d key(s) now.", name, len(keys)),
		})
	}

	cmd.Printf("The machine %q has %d key(s) now.\n", name, len(keys))
	cmd.Println("Re-encrypt the groups it is in so the new keys can read them: chezmoi sops sync")
	return nil
}

func newMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members <group> [machine ...]",
		Short: "Show or change the machines that may read a group",
		Long: `Show or change the machines that may read a group.

Without a machine, the current members are listed. With machines, they are
replaced by the given ones.

The members decide who may read the group: the recipients of its payloads
are the age keys of its members. Adding a member therefore means
re-encrypting the payloads for that key, which this command does.`,
		Args: cobra.ArbitraryArgs,
		RunE: runMembers,
	}
	cmd.Flags().Bool("no-reencrypt", false, "do not re-encrypt the payloads of the group")
	addJSONFlag(cmd)
	return cmd
}

func runMembers(cmd *cobra.Command, args []string) error {
	noReencrypt, _ := cmd.Flags().GetBool("no-reencrypt")

	environment, err := resolve()
	if err != nil {
		return err
	}

	// Without a group, every group is listed with its members.
	if len(args) == 0 {
		return runGroups(cmd, args)
	}

	name := args[0]
	members := args[1:]

	group, ok := environment.Layout.Access.Group(name)
	if !ok {
		return fail("The group %q does not exist.", name)
	}

	if len(members) == 0 {
		if jsonRequested(cmd) {
			return printJSON(cmd, jsonOutput{
				Command: "members",
				OK:      true,
				Groups: []jsonGroup{{
					Name:       group.Name,
					Hosts:      group.Members,
					Recipients: environment.recipientsOf(group.Name),
				}},
			})
		}
		cmd.Printf("%s\n", strings.Join(group.Members, ", "))
		return nil
	}

	for _, member := range members {
		if _, ok := environment.Layout.Access.Host(member); !ok {
			return fail("The host %q is not in %s.", member, access.FileName)
		}
	}

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
			Command: "members",
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
		cmd.Println("Run 'chezmoi sops edit group/" + name + "' to encrypt them again.")
	}
	return nil
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

func newHostsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hosts",
		Short: "Show the machines and their age keys",
		Long: `Show the machines and their age keys.

A machine can have more than one key, for example one for the native
system and one for a virtual machine.`,
		Args: cobra.NoArgs,
		RunE: runHosts,
	}
	addJSONFlag(cmd)
	return cmd
}

func runHosts(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	if jsonRequested(cmd) {
		output := jsonOutput{Command: "hosts", OK: true}
		for _, host := range environment.Layout.Hosts {
			output.Hosts = append(output.Hosts, jsonHost{
				Host:   host.Hostname(),
				Key:    strings.Join(host.Age, ", "),
				Groups: environment.groupsOfHost(host.Name),
			})
		}
		return printJSON(cmd, output)
	}

	for _, host := range environment.Layout.Hosts {
		cmd.Printf("%s\n", host.Hostname())
		for _, key := range host.Age {
			cmd.Printf("    %s\n", key)
		}
	}

	return nil
}
