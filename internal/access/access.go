// Package access reads the access file: the single description of which
// machines exist and which groups of secrets they may read.
//
// The access file is the only place the access control is written down. The
// recipients of a group are derived from the members of that group, so a key
// is never written twice.
package access

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the name of the access file inside the secrets directory.
const FileName = "access.yaml"

// Machine is a machine that has an age identity.
type Machine struct {
	// Name is the key of the machine in the access file. It is also the name
	// of the machine's directory.
	Name string

	// Label is an optional human-readable name.
	Label string

	// Hostnames are the hostnames the machine is known by. When it is
	// empty, the name is matched instead.
	Hostnames []string

	// Age are the age public keys of the machine.
	Age []string
}

// Group is a set of machines that may read the same secrets.
type Group struct {
	// Name is the key of the group in the access file. It is also the name
	// of the group's directory.
	Name string

	// Members are the names of the machines that may read the group.
	Members []string
}

// File is the parsed access file.
type File struct {
	// Path is where the file was read from.
	Path string

	// Machines are the machines, in the order they appear in the file.
	Machines []Machine

	// Groups are the groups, in the order they appear in the file.
	//
	// The order matters: the groups are merged in this order, and the
	// first one that holds a value wins.
	Groups []Group

	// document is the parsed file. It is kept so the file can be edited
	// without losing the comments in it.
	document *yaml.Node

	// root is the top-level mapping of the document.
	root *yaml.Node
}

// Machine returns the machine with the given name.
func (f *File) Machine(name string) (Machine, bool) {
	for _, machine := range f.Machines {
		if machine.Name == name {
			return machine, true
		}
	}
	return Machine{}, false
}

// RecipientsOf returns the age public keys a group is encrypted for.
//
// They are the keys of the members of the group, so a key is only ever
// written once.
func (f *File) RecipientsOf(name string) []string {
	group, ok := f.Group(name)
	if !ok {
		return nil
	}

	var recipients []string
	for _, member := range group.Members {
		machine, ok := f.Machine(member)
		if !ok {
			continue
		}
		recipients = append(recipients, machine.Age...)
	}
	return recipients
}

// Group returns the group with the given name.
func (f *File) Group(name string) (Group, bool) {
	for _, group := range f.Groups {
		if group.Name == name {
			return group, true
		}
	}
	return Group{}, false
}

// Load reads and validates the access file.
//
// The order of the machines and the groups is preserved, because it decides
// which value wins when two of them hold the same key.
func Load(path string) (*File, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}

	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s must contain a mapping at the top level", path)
	}

	file := &File{Path: path}

	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		value := root.Content[i+1]

		switch key {
		case "machines", "hosts":
			// The section was called "hosts" before 0.5.0. Both names are
			// read, and the key is renamed in the document as it is read,
			// so that saving writes the new name. This lets a machine
			// that has not been updated yet keep working against a
			// repository that has, and it can be dropped once every
			// machine has been updated.
			if key == "hosts" {
				root.Content[i].Value = "machines"
			}
			machines, err := decodeMachines(value)
			if err != nil {
				return nil, fmt.Errorf("%s: machines: %w", path, err)
			}
			file.Machines = machines
		case "groups":
			groups, err := decodeGroups(value)
			if err != nil {
				return nil, fmt.Errorf("%s: groups: %w", path, err)
			}
			file.Groups = groups
		default:
			return nil, fmt.Errorf("%s: unknown key %q", path, key)
		}
	}

	if err := file.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	file.document = &document
	file.root = root
	return file, nil
}

// validate checks that the file is consistent.
func (f *File) validate() error {
	seenMachines := map[string]bool{}
	for _, machine := range f.Machines {
		if seenMachines[machine.Name] {
			return fmt.Errorf("the machine %q is defined twice", machine.Name)
		}
		seenMachines[machine.Name] = true

		if len(machine.Age) == 0 {
			return fmt.Errorf("the machine %q has no age key", machine.Name)
		}
	}

	seenGroups := map[string]bool{}
	for _, group := range f.Groups {
		if seenGroups[group.Name] {
			return fmt.Errorf("the group %q is defined twice", group.Name)
		}
		seenGroups[group.Name] = true

		seenMembers := map[string]bool{}
		for _, member := range group.Members {
			if seenMembers[member] {
				return fmt.Errorf("the group %q lists the machine %q twice", group.Name, member)
			}
			seenMembers[member] = true

			// Every member has to be a known machine: a key without a name
			// is a key nobody knows the owner of.
			if !seenMachines[member] {
				return fmt.Errorf("the group %q lists the unknown machine %q", group.Name, member)
			}
		}
	}

	return nil
}

// decodeMachines decodes the machines section, preserving its order.
func decodeMachines(node *yaml.Node) ([]Machine, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("must be a mapping of machine names")
	}

	var machines []Machine
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1]

		if value.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("the machine %q must be a mapping", name)
		}

		machine := Machine{Name: name}
		for j := 0; j+1 < len(value.Content); j += 2 {
			key := value.Content[j].Value
			entry := value.Content[j+1]

			switch key {
			case "age":
				var keys AgeKeys
				if err := entry.Decode(&keys); err != nil {
					return nil, fmt.Errorf("the machine %q: age: %w", name, err)
				}
				machine.Age = keys
			case "label":
				if err := entry.Decode(&machine.Label); err != nil {
					return nil, fmt.Errorf("the machine %q: label: %w", name, err)
				}
			case "hostnames":
				if err := entry.Decode(&machine.Hostnames); err != nil {
					return nil, fmt.Errorf("the machine %q: hostnames: %w", name, err)
				}
			default:
				return nil, fmt.Errorf("the machine %q: unknown key %q", name, key)
			}
		}

		machines = append(machines, machine)
	}

	return machines, nil
}

// decodeGroups decodes the groups section, preserving its order.
func decodeGroups(node *yaml.Node) ([]Group, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("must be a mapping of group names")
	}

	var groups []Group
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		value := node.Content[i+1]

		var group Group
		group.Name = name

		switch value.Kind {
		case yaml.SequenceNode:
			if err := value.Decode(&group.Members); err != nil {
				return nil, fmt.Errorf("the group %q: %w", name, err)
			}
		case yaml.ScalarNode:
			// A single member is a common enough case to allow.
			var member string
			if err := value.Decode(&member); err != nil {
				return nil, fmt.Errorf("the group %q: %w", name, err)
			}
			group.Members = []string{member}
		default:
			return nil, fmt.Errorf("the group %q must be a list of machine names", name)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// AgeKeys is a list of age public keys.
//
// It accepts both a single key and a list of keys, because a machine with
// one key is the common case.
type AgeKeys []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *AgeKeys) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var key string
		if err := node.Decode(&key); err != nil {
			return err
		}
		*a = AgeKeys{key}
		return nil
	case yaml.SequenceNode:
		var keys []string
		if err := node.Decode(&keys); err != nil {
			return err
		}
		*a = keys
		return nil
	default:
		return fmt.Errorf("must be a key or a list of keys")
	}
}

// MatchesHostname reports whether the machine is the machine with the given
// hostname.
//
// The hostnames of the machine win. Without them the name is matched, first
// exactly and then by prefix, which is the convention the recipient
// registry used: a machine named "SE-CND235268L / worklaptop" is the machine
// whose hostname is "SE-CND235268L".
func (h Machine) MatchesHostname(hostname string) bool {
	if hostname == "" {
		return false
	}

	if len(h.Hostnames) > 0 {
		// The explicit hostnames replace the name: they are there for the
		// cases the convention cannot express.
		for _, candidate := range h.Hostnames {
			if strings.EqualFold(candidate, hostname) {
				return true
			}
		}
		return false
	}

	if strings.EqualFold(h.Name, hostname) {
		return true
	}

	return strings.HasPrefix(strings.ToLower(h.Name), strings.ToLower(hostname))
}

// Hostname returns the name to show for the machine.
func (h Machine) Hostname() string {
	if h.Label != "" {
		return h.Label
	}
	return h.Name
}
