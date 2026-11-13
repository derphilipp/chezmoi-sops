package cli

import (
	"fmt"
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/access"
)

// accessPath returns the path of the access file.
func (e *env) accessPath() string {
	return e.secretsDir() + string(os.PathSeparator) + access.FileName
}

// addGroup adds a group to the access file.
//
// The group is added before its directory is created, so the layout is
// never in a state the tool refuses to read.
func (e *env) addGroup(name string, members []string) error {
	for _, member := range members {
		if _, ok := e.Layout.Access.Machine(member); !ok {
			return fmt.Errorf("the machine %q is not in %s", member, access.FileName)
		}
	}

	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}
	if err := file.AddGroup(name, members); err != nil {
		return err
	}
	return file.Save()
}

// addMachine adds a machine with its age keys to the access file.
func (e *env) addMachine(name string, keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("a machine needs at least one age key")
	}

	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}
	if err := file.AddMachine(name, keys); err != nil {
		return err
	}
	return file.Save()
}

// setMachineKeys replaces the age keys of a machine.
func (e *env) setMachineKeys(name string, keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("a machine needs at least one age key")
	}

	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}
	if err := file.SetMachineKeys(name, keys); err != nil {
		return err
	}
	return file.Save()
}

// setMembers replaces the members of a group.
func (e *env) setMembers(name string, members []string) error {
	for _, member := range members {
		if _, ok := e.Layout.Access.Machine(member); !ok {
			return fmt.Errorf("the machine %q is not in %s", member, access.FileName)
		}
	}

	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}
	if err := file.SetGroupMembers(name, members); err != nil {
		return err
	}
	return file.Save()
}

// removeEntry removes a group or a machine from the access file.
func (e *env) removeEntry(t target) error {
	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}

	switch t.Kind {
	case kindGroup:
		err = file.RemoveGroup(t.Name)
	case kindMachine:
		err = file.RemoveMachine(t.Name)
	default:
		err = fmt.Errorf("unknown kind %q", t.Kind)
	}
	if err != nil {
		return err
	}

	return file.Save()
}

// newRecipients returns the age public keys a group is encrypted for, read
// from the access file as it is now.
//
// The layout was read before the change, so it holds the old recipients.
// The file that was just written holds the new ones.
func (e *env) newRecipients(name string) ([]string, error) {
	file, err := access.Load(e.accessPath())
	if err != nil {
		return nil, err
	}
	return file.RecipientsOf(name), nil
}
