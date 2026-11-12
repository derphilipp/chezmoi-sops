package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/spf13/cobra"
)

func newRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <group|host>/<old> <group|host>/<new>",
		Short: "Rename a group or a machine",
		Long: `Rename a group or a machine.

The entry in the access file and the directory are renamed together, so the
layout stays consistent. The payloads are not touched.

Both sides have to be of the same kind: a group cannot become a machine.
`,
		Args: cobra.ExactArgs(2),
		RunE: runRename,
	}
	addJSONFlag(cmd)
	return cmd
}

func runRename(cmd *cobra.Command, args []string) error {
	from, err := parseTarget(args[0])
	if err != nil {
		return fail("%s", err)
	}
	to, err := parseTarget(args[1])
	if err != nil {
		return fail("%s", err)
	}

	if from.Kind != to.Kind {
		return fail("A %s cannot become a %s.", from.Kind, to.Kind)
	}
	if from.File != "" || to.File != "" {
		return fail("Only a whole group or machine can be renamed.")
	}
	if from.Name == to.Name {
		return fail("The name did not change.")
	}

	environment, err := resolve()
	if err != nil {
		return err
	}

	file, err := access.Load(environment.accessPath())
	if err != nil {
		return fail("%s", err)
	}

	switch from.Kind {
	case groups.KindGroup:
		if _, ok := file.Group(from.Name); !ok {
			return fail("The group %q does not exist.", from.Name)
		}
		if _, ok := file.Group(to.Name); ok {
			return fail("The group %q already exists.", to.Name)
		}
		// The members move with the group.
		group, _ := file.Group(from.Name)
		file.RemoveGroup(from.Name)
		if err := file.AddGroup(to.Name, group.Members); err != nil {
			return fail("%s", err)
		}
	case groups.KindHost:
		if _, ok := file.Host(from.Name); !ok {
			return fail("The host %q does not exist.", from.Name)
		}
		if _, ok := file.Host(to.Name); ok {
			return fail("The host %q already exists.", to.Name)
		}
		host, _ := file.Host(from.Name)
		file.RemoveHost(from.Name)
		if err := file.AddHost(to.Name, host.Age); err != nil {
			return fail("%s", err)
		}
		// The groups the machine was in keep it.
		for i, group := range file.Groups {
			for j, member := range group.Members {
				if member == from.Name {
					file.Groups[i].Members[j] = to.Name
				}
			}
		}
	}

	if err := file.Save(); err != nil {
		return fail("%s", err)
	}

	// The directory carries the name too.
	oldDir := filepath.Join(environment.secretsDir(), from.Kind+"s", from.Name)
	newDir := filepath.Join(environment.secretsDir(), to.Kind+"s", to.Name)

	if _, err := os.Stat(oldDir); err == nil {
		if _, err := os.Stat(newDir); err == nil {
			return fail("The directory %s already exists.", newDir)
		}
		if err := os.Rename(oldDir, newDir); err != nil {
			return fail("Renaming %s to %s: %s", oldDir, newDir, err)
		}
	}

	if jsonRequested(cmd) {
		return printJSON(jsonOutput{
			Command: "rename",
			OK:      true,
			Message: fmt.Sprintf("Renamed %s to %s.", from, to),
		})
	}

	fmt.Printf("Renamed %s to %s.\n", from, to)
	return nil
}
