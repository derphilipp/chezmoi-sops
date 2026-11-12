package cli

import (
	"fmt"
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
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
		if _, ok := e.Layout.Access.Host(member); !ok {
			return fmt.Errorf("the host %q is not in %s", member, access.FileName)
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

// addHost adds a machine with its age keys to the access file.
func (e *env) addHost(name string, keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("a machine needs at least one age key")
	}

	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}
	if err := file.AddHost(name, keys); err != nil {
		return err
	}
	return file.Save()
}

// setHostKeys replaces the age keys of a machine.
func (e *env) setHostKeys(name string, keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("a machine needs at least one age key")
	}

	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}
	if err := file.SetHostKeys(name, keys); err != nil {
		return err
	}
	return file.Save()
}

// setMembers replaces the members of a group.
func (e *env) setMembers(name string, members []string) error {
	for _, member := range members {
		if _, ok := e.Layout.Access.Host(member); !ok {
			return fmt.Errorf("the host %q is not in %s", member, access.FileName)
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

// removeEntry removes a group or a host from the access file.
func (e *env) removeEntry(t target) error {
	file, err := access.Load(e.accessPath())
	if err != nil {
		return err
	}

	switch t.Kind {
	case groups.KindGroup:
		err = file.RemoveGroup(t.Name)
	case groups.KindHost:
		err = file.RemoveHost(t.Name)
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
