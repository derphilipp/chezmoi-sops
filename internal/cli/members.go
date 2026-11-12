package cli

import (
	"fmt"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/spf13/cobra"
)

func newMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members <group> [host ...]",
		Short: "Show or change the hosts that may read a group",
		Long: `Show or change the hosts that may read a group.

Without a host, the current members are listed. With hosts, they are
replaced by the given ones.

The members decide who may read the group: the recipients of its payloads
are the age keys of its members. Adding a member therefore means
re-encrypting the payloads for that key.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runMembers,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMembers(cmd *cobra.Command, args []string) error {
	name := args[0]
	members := args[1:]

	environment, err := resolve()
	if err != nil {
		return err
	}

	group, ok := environment.Layout.Access.Group(name)
	if !ok {
		return fail("The group %q does not exist.", name)
	}

	if len(members) == 0 {
		if jsonRequested(cmd) {
			return printJSON(jsonOutput{
				Command: "members",
				OK:      true,
				Groups: []jsonGroup{{
					Name:       group.Name,
					Hosts:      group.Members,
					Recipients: environment.Layout.Groups[groupIndex(environment, name)].Recipients,
				}},
			})
		}
		fmt.Printf("%s\n", strings.Join(group.Members, ", "))
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

	if jsonRequested(cmd) {
		return printJSON(jsonOutput{
			Command: "members",
			OK:      true,
			Message: fmt.Sprintf("The group %q is now read by %s.", name, strings.Join(members, ", ")),
		})
	}

	fmt.Printf("The group %q is now read by %s.\n", name, strings.Join(members, ", "))
	fmt.Println("Re-encrypt its payloads so the new members can read them: chezmoi sops edit group/" + name)
	return nil
}

// groupIndex returns the position of a group in the layout.
func groupIndex(environment *env, name string) int {
	for i, group := range environment.Layout.Groups {
		if group.Name == name {
			return i
		}
	}
	return 0
}

// setMembers replaces the members of a group.
func (e *env) setMembers(name string, members []string) error {
	return e.rewriteAccess(func(file *access.File) {
		for i, group := range file.Groups {
			if group.Name == name {
				file.Groups[i].Members = members
			}
		}
	})
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
		return printJSON(output)
	}

	for _, host := range environment.Layout.Hosts {
		fmt.Printf("%s\n", host.Hostname())
		for _, key := range host.Age {
			fmt.Printf("    %s\n", key)
		}
	}

	return nil
}
