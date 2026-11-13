package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/editor"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
	"github.com/spf13/cobra"
)

// The kinds of things the secrets belong to.
//
// The machines are called machines in the access file and in the layout: that
// is where the names live. The command line and the messages call them
// machines, because that is what they are.
const (
	kindGroup   = "group"
	kindMachine = "machine"
)

// target is a group or a machine, and optionally a file inside it.
type target struct {
	// Kind is kindGroup or kindMachine.
	Kind string

	// Name is the name of the group or the machine.
	Name string

	// File is the payload file inside it. It is empty when the whole
	// group or machine is edited.
	File string
}

// String returns the target as it is shown to the user.
func (t target) String() string {
	if t.File == "" {
		return t.Name
	}
	return t.Name + "/" + t.File
}

// targetDir returns the directory of a group or a machine, and the
// recipients its payloads are encrypted for.
func (e *env) targetDir(t target) (string, []string, error) {
	switch t.Kind {
	case kindGroup:
		for _, group := range e.Layout.Groups {
			if group.Name == t.Name {
				return group.Dir, group.Recipients, nil
			}
		}
		return "", nil, fmt.Errorf("The group %q does not exist.", t.Name)
	case kindMachine:
		for _, machine := range e.Layout.Machines {
			if machine.Name == t.Name {
				return machine.Dir, machine.Age, nil
			}
		}
		return "", nil, fmt.Errorf("The machine %q does not exist.", t.Name)
	default:
		return "", nil, fmt.Errorf("Unknown kind %q.", t.Kind)
	}
}

// secretsDirOf returns the directory that holds the payloads of a group or
// a machine.
func (e *env) secretsDirOf(kind string) string {
	if kind == kindMachine {
		return groups.MachinesDir
	}
	return groups.GroupsDir
}

// editTarget decrypts the payloads of a group or a machine, opens them in
// the editor and encrypts them again.
//
// The file is the payload file inside the group or the machine. It is empty
// when every payload is edited in one editor session.
func editTarget(cmd *cobra.Command, kind, name, file string) error {
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

	t := target{Kind: kind, Name: name, File: file}

	dir, recipients, err := environment.targetDir(t)
	if err != nil {
		return fail("%s", err)
	}

	// A group or a machine may have no payloads yet. Its directory is
	// created here, so the first payload has a place to go.
	if dir == "" {
		dir = filepath.Join(environment.secretsDir(), environment.secretsDirOf(kind), name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fail("Creating %s: %s", dir, err)
		}
	}

	files, err := groups.Payloads(dir)
	if err != nil {
		return fail("%s", err)
	}
	if file != "" {
		files = []string{filepath.Join(dir, file)}
	}

	if len(files) == 0 {
		// A group without a payload is a group that has just been
		// created: the first payload is created here.
		files = []string{filepath.Join(dir, name+".sops.yaml")}
	}

	for _, path := range files {
		format := groups.FormatOf(path)
		if wantSOPS {
			format = "sops"
		}
		if wantAge {
			format = "age"
		}

		newFile := path
		if format != groups.FormatOf(path) {
			newFile = replaceFormat(path, format)
		}

		if err := environment.editFile(newFile, path, format, recipients, force, flagEditor); err != nil {
			return fail("%s", err)
		}
	}

	return nil
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

// deleteTarget removes a group or a machine, with its payloads.
func deleteTarget(cmd *cobra.Command, kind, name string) error {
	environment, err := resolve()
	if err != nil {
		return err
	}

	t := target{Kind: kind, Name: name}

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
		return printJSON(cmd, jsonOutput{
			Command: kind + " delete",
			OK:      true,
			Message: fmt.Sprintf("Deleted the %s %q.", kind, name),
			Removed: removed,
		})
	}

	for _, path := range removed {
		cmd.Printf("Removed %s\n", path)
	}
	cmd.Println("Run 'chezmoi init && chezmoi apply' to apply the change.")
	return nil
}

// renameTarget renames a group or a machine.
//
// The entry in the access file and the directory are renamed together, so
// the layout stays consistent. The payloads are not touched.
func renameTarget(cmd *cobra.Command, kind, from, to string) error {
	if from == to {
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

	switch kind {
	case kindGroup:
		if _, ok := file.Group(from); !ok {
			return fail("The group %q does not exist.", from)
		}
		if _, ok := file.Group(to); ok {
			return fail("The group %q already exists.", to)
		}
		// The members move with the group.
		group, _ := file.Group(from)
		file.RemoveGroup(from)
		if err := file.AddGroup(to, group.Members); err != nil {
			return fail("%s", err)
		}
	case kindMachine:
		if _, ok := file.Machine(from); !ok {
			return fail("The machine %q does not exist.", from)
		}
		if _, ok := file.Machine(to); ok {
			return fail("The machine %q already exists.", to)
		}
		machine, _ := file.Machine(from)
		file.RemoveMachine(from)
		if err := file.AddMachine(to, machine.Age); err != nil {
			return fail("%s", err)
		}
		// The groups the machine was in keep it.
		for i, group := range file.Groups {
			for j, member := range group.Members {
				if member == from {
					file.Groups[i].Members[j] = to
				}
			}
		}
	}

	if err := file.Save(); err != nil {
		return fail("%s", err)
	}

	// The directory carries the name too.
	oldDir := filepath.Join(environment.secretsDir(), environment.secretsDirOf(kind), from)
	newDir := filepath.Join(environment.secretsDir(), environment.secretsDirOf(kind), to)

	if _, err := os.Stat(oldDir); err == nil {
		if _, err := os.Stat(newDir); err == nil {
			return fail("The directory %s already exists.", newDir)
		}
		if err := os.Rename(oldDir, newDir); err != nil {
			return fail("Renaming %s to %s: %s", oldDir, newDir, err)
		}
	}

	if jsonRequested(cmd) {
		return printJSON(cmd, jsonOutput{
			Command: kind + " rename",
			OK:      true,
			Message: fmt.Sprintf("Renamed the %s %q to %q.", kind, from, to),
		})
	}

	cmd.Printf("Renamed the %s %q to %q.\n", kind, from, to)
	return nil
}
