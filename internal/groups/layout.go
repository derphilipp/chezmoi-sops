package groups

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
)

// Directory names inside the secrets directory.
const (
	// GroupsDir holds the groups of secrets.
	GroupsDir = "groups"

	// MachinesDir holds the secrets of the individual machines.
	MachinesDir = "machines"
)

// Group is a set of machines that may read the same secrets.
type Group struct {
	// Name is the name of the group.
	Name string

	// Dir is the directory that holds the group's payload files. It is
	// empty when the group has no files.
	Dir string

	// Members are the names of the machines that may read the group.
	Members []string

	// Recipients are the age public keys the group's payloads are
	// encrypted for. They are the keys of the members.
	Recipients []string
}

// Machine is a machine that has its own secrets.
type Machine struct {
	// Machine is the machine as it is written in the access file.
	access.Machine

	// Dir is the directory that holds the machine's payload files. It is
	// empty when the machine has no files.
	Dir string
}

// Layout is the discovered layout of the secrets directory.
//
//	.secrets/
//	  access.yaml
//	  groups/<group>/<file>
//	  machines/<machine>/<file>
type Layout struct {
	// Dir is the secrets directory.
	Dir string

	// Access is the parsed access file.
	Access *access.File

	// Groups are the groups, in the order of the access file.
	Groups []Group

	// Machines are the machines, in the order of the access file.
	Machines []Machine
}

// Discover reads the layout of the secrets directory.
//
// The access file is the only description of the access control. A directory
// that is not in the access file is an error: it would either be readable by
// nobody or by everybody, and neither is ever meant.
func Discover(dir string) (Layout, error) {
	layout := Layout{Dir: dir}

	file, err := access.Load(filepath.Join(dir, access.FileName))
	if err != nil {
		return layout, err
	}
	layout.Access = file

	for _, machine := range file.Machines {
		resolved := Machine{Machine: machine}

		machineDir := filepath.Join(dir, MachinesDir, machine.Name)
		if info, err := os.Stat(machineDir); err == nil && info.IsDir() {
			resolved.Dir = machineDir
		}

		layout.Machines = append(layout.Machines, resolved)
	}

	for _, group := range file.Groups {
		resolved := Group{
			Name:    group.Name,
			Members: group.Members,
		}

		for _, member := range group.Members {
			machine, ok := file.Machine(member)
			if !ok {
				return layout, fmt.Errorf("the group %q lists the unknown machine %q", group.Name, member)
			}
			resolved.Recipients = append(resolved.Recipients, machine.Age...)
		}

		groupDir := filepath.Join(dir, GroupsDir, group.Name)
		if info, err := os.Stat(groupDir); err == nil && info.IsDir() {
			resolved.Dir = groupDir
		}

		layout.Groups = append(layout.Groups, resolved)
	}

	if err := layout.checkForgotten(dir); err != nil {
		return layout, err
	}

	return layout, nil
}

// checkForgotten reports the directories that are not in the access file.
func (l Layout) checkForgotten(dir string) error {
	for _, kind := range []string{MachinesDir, GroupsDir} {
		entries, err := os.ReadDir(filepath.Join(dir, kind))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("reading %s: %w", filepath.Join(dir, kind), err)
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			switch kind {
			case MachinesDir:
				if _, ok := l.Access.Machine(entry.Name()); !ok {
					return fmt.Errorf("the directory %s/%s has no entry in %s: "+
						"every machine needs a name and its keys. If the machine was "+
						"renamed, rename the directory as well",
						kind, entry.Name(), access.FileName)
				}
			case GroupsDir:
				if _, ok := l.Access.Group(entry.Name()); !ok {
					return fmt.Errorf("the directory %s/%s has no entry in %s: "+
						"every group needs its members. If the group was renamed, "+
						"rename the directory as well",
						kind, entry.Name(), access.FileName)
				}
			}
		}
	}

	return nil
}

// Payloads returns the payload files of a directory, in alphabetical order.
//
// The order decides which value wins when two files hold the same key.
func Payloads(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}

	sort.Strings(paths)
	return paths, nil
}

// FormatOf returns the payload format of a file, from its name.
//
// A file that ends in ".sops.yaml" is in the sops format, a file that ends
// in ".age" is in the whole-file age format.
func FormatOf(path string) string {
	switch {
	case strings.HasSuffix(path, ".sops.yaml"):
		return "sops"
	case strings.HasSuffix(path, ".age"):
		return "age"
	default:
		return "sops"
	}
}

// ForHostname returns the machine known by the given hostname.
//
// The hostnames of a machine win. Without them the name is matched, first
// exactly and then by prefix, which is the convention the recipient
// registry used.
func (l Layout) ForHostname(hostname string) (Machine, bool) {
	for _, machine := range l.Machines {
		if machine.MatchesHostname(hostname) {
			return machine, true
		}
	}
	return Machine{}, false
}
