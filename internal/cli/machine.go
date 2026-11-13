package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// newMachineCmd builds the command that manages the machines.
func newMachineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machine",
		Short: "Manage the machines",
		Long: `Manage the machines.

A machine has its own age keys and its own private secrets. The groups it
may read are its memberships, and it reads the payloads of those groups
because it is a member of them.`,
	}

	cmd.AddCommand(
		newMachineListCmd(),
		newMachineCreateCmd(),
		newMachineEditCmd(),
		newMachineKeysCmd(),
		newMachineRenameCmd(),
		newMachineDeleteCmd(),
	)

	return cmd
}

func newMachineListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the machines, their keys, and the groups they may read",
		Long: `Show the machines, their keys, and the groups they may read.

A machine can have more than one key, for example one for the native system
and one for a virtual machine.`,
		Args: cobra.NoArgs,
		RunE: runMachineList,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMachineList(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	if jsonRequested(cmd) {
		output := jsonOutput{Command: "machine list", OK: true}
		for _, machine := range environment.Layout.Hosts {
			output.Machines = append(output.Machines, jsonMachine{
				Machine: machine.Hostname(),
				Key:     strings.Join(machine.Age, ", "),
				Groups:  environment.groupsOfMachine(machine.Name),
			})
		}
		return printJSON(cmd, output)
	}

	cmd.Println()
	cmd.Println("Machines")
	for _, machine := range environment.Layout.Hosts {
		readable := environment.groupsOfMachine(machine.Name)
		cmd.Printf("  %-24s %s\n", machine.Hostname(), strings.Join(readable, ", "))
		for _, key := range machine.Age {
			cmd.Printf("      %s\n", key)
		}
	}
	cmd.Println()

	return nil
}

func newMachineCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name> <age key>...",
		Short: "Create a machine with its age keys",
		Long: `Create a machine with its age keys.

The machine is added to the access file and gets a directory to hold the
secrets of its own. The age keys are its public keys: they are what the
groups it may read are encrypted for.

The secrets a machine shares with other machines belong to a group: create
one with "chezmoi sops group create".`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: completeMachines,
		RunE:              runMachineCreate,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMachineCreate(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	name := args[0]
	keys := args[1:]

	if _, ok := environment.Layout.Access.Host(name); ok {
		return fail("The machine %q already exists.", name)
	}

	// The access file is written first: a directory without an entry in it
	// is a state the tool refuses to read.
	if err := environment.addMachine(name, keys); err != nil {
		return fail("%s", err)
	}

	dir := filepath.Join(environment.secretsDir(), environment.secretsDirOf(kindMachine), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("Creating %s: %s", dir, err)
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: "machine create",
			OK:      true,
			Message: fmt.Sprintf("Created the machine %q.", name),
		})
	}

	cmd.Printf("Created the machine %q: %s\n", name, dir)
	return nil
}

func newMachineEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name> [file]",
		Short: "Decrypt the secrets of a machine, open them in the editor, and re-encrypt them",
		Long: `Decrypt the secrets of a machine, open them in the editor, and re-encrypt them.

The payload is decrypted with the identity of this machine. When the
machine cannot decrypt it, the payload is not overwritten unless --force is
given.

Without a file, every payload of the machine is opened in one editor session.`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completeMachineTarget,
		RunE:              runMachineEdit,
	}
	cmd.Flags().BoolP("force", "f", false, "overwrite without decrypting first")
	cmd.Flags().Bool("sops", false, "convert the payload to the sops format")
	cmd.Flags().Bool("age", false, "convert the payload to the whole-file age format")
	addJSONFlag(cmd)
	return cmd
}

func runMachineEdit(cmd *cobra.Command, args []string) error {
	return editTarget(cmd, kindMachine, args[0], optionalFile(args))
}

func newMachineKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys <name> [age key...]",
		Short: "Show or set the age keys of a machine",
		Long: `Show or set the age keys of a machine.

Without a key, the keys of the machine are listed. With keys, they are
replaced.

A machine may have more than one key, for example one for the native
system and one for a virtual machine.

Changing the keys does not encrypt the payloads of the groups the machine
is in again. Run "chezmoi sops sync" afterwards, or edit the groups by
hand.`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completeMachines,
		RunE:              runMachineKeys,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMachineKeys(cmd *cobra.Command, args []string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	name := args[0]
	keys := args[1:]

	machine, ok := environment.Layout.Access.Host(name)
	if !ok {
		return fail("The machine %q does not exist.", name)
	}

	if len(keys) == 0 {
		if jsonRequested(cmd) {
			return printJSON(cmd, jsonOutput{
				Command: "machine keys",
				OK:      true,
				Machines: []jsonMachine{{
					Machine: machine.Hostname(),
					Key:     strings.Join(machine.Age, ", "),
					Groups:  environment.groupsOfMachine(name),
				}},
			})
		}
		cmd.Printf("%s\n", machine.Hostname())
		for _, key := range machine.Age {
			cmd.Printf("    %s\n", key)
		}
		return nil
	}

	if err := environment.setMachineKeys(name, keys); err != nil {
		return fail("%s", err)
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: "machine keys",
			OK:      true,
			Message: fmt.Sprintf("The machine %q has %d key(s) now.", name, len(keys)),
		})
	}

	cmd.Printf("The machine %q has %d key(s) now.\n", name, len(keys))
	cmd.Println("Encrypt the groups it is in again so the new keys can read them: chezmoi sops sync")
	return nil
}

func newMachineRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a machine",
		Long: `Rename a machine.

The entry in the access file and the directory are renamed together, so the
layout stays consistent. The groups the machine is in keep it, and the
payloads are not touched.`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeMachines,
		RunE:              runMachineRename,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMachineRename(cmd *cobra.Command, args []string) error {
	return renameTarget(cmd, kindMachine, args[0], args[1])
}

func newMachineDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Remove a machine and its secrets",
		Long: `Remove a machine and its secrets.

The payload directory is removed and the entry is removed from the access
file. The machine is removed from the groups it was a member of.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeMachines,
		RunE:              runMachineDelete,
	}
	addJSONFlag(cmd)
	return cmd
}

func runMachineDelete(cmd *cobra.Command, args []string) error {
	return deleteTarget(cmd, kindMachine, args[0])
}
