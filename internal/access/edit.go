package access

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// indent is the indentation of the access file.
const indent = 2

// Save writes the access file back.
//
// The file is written from the document it was parsed from, so the comments
// and the formatting of the file survive. The access file is meant to be
// read and edited by a human, so nothing in it may be lost.
func (f *File) Save() error {
	var out []byte
	{
		var buf yamlBuffer
		encoder := yaml.NewEncoder(&buf)
		encoder.SetIndent(indent)
		if err := encoder.Encode(f.document); err != nil {
			return fmt.Errorf("encoding %s: %w", f.Path, err)
		}
		if err := encoder.Close(); err != nil {
			return fmt.Errorf("encoding %s: %w", f.Path, err)
		}
		out = buf.data
	}

	return os.WriteFile(f.Path, out, 0o600)
}

// yamlBuffer collects the output of a YAML encoder.
type yamlBuffer struct {
	data []byte
}

// Write implements io.Writer.
func (b *yamlBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

// AddMachine adds a machine with its age keys.
func (f *File) AddMachine(name string, keys []string) error {
	if _, ok := f.Machine(name); ok {
		return fmt.Errorf("the machine %q already exists", name)
	}

	machine := Machine{Name: name, Age: keys}
	f.Machines = append(f.Machines, machine)

	mapping := f.section("machines")
	mapping.Content = append(mapping.Content, scalarNode(name), machineNode(machine))
	return nil
}

// SetMachineKeys replaces the age keys of a machine.
func (f *File) SetMachineKeys(name string, keys []string) error {
	machine, ok := f.Machine(name)
	if !ok {
		return fmt.Errorf("the machine %q does not exist", name)
	}

	machine.Age = keys
	for i := range f.Machines {
		if f.Machines[i].Name == name {
			f.Machines[i] = machine
		}
	}

	mapping := f.section("machines")
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != name {
			continue
		}
		mapping.Content[i+1] = machineNode(machine)
		return nil
	}
	return fmt.Errorf("the machine %q does not exist", name)
}

// RemoveMachine removes a machine.
func (f *File) RemoveMachine(name string) error {
	if _, ok := f.Machine(name); !ok {
		return fmt.Errorf("the machine %q does not exist", name)
	}

	var machines []Machine
	for _, machine := range f.Machines {
		if machine.Name != name {
			machines = append(machines, machine)
		}
	}
	f.Machines = machines

	mapping := f.section("machines")
	mapping.Content = mappingDelete(mapping.Content, name)
	return nil
}

// AddGroup adds a group with its members.
func (f *File) AddGroup(name string, members []string) error {
	if _, ok := f.Group(name); ok {
		return fmt.Errorf("the group %q already exists", name)
	}

	group := Group{Name: name, Members: members}
	f.Groups = append(f.Groups, group)

	mapping := f.section("groups")
	mapping.Content = append(mapping.Content, scalarNode(name), groupNode(group))
	return nil
}

// SetGroupMembers replaces the members of a group.
func (f *File) SetGroupMembers(name string, members []string) error {
	group, ok := f.Group(name)
	if !ok {
		return fmt.Errorf("the group %q does not exist", name)
	}

	group.Members = members
	for i := range f.Groups {
		if f.Groups[i].Name == name {
			f.Groups[i] = group
		}
	}

	mapping := f.section("groups")
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != name {
			continue
		}
		mapping.Content[i+1] = groupNode(group)
		return nil
	}
	return fmt.Errorf("the group %q does not exist", name)
}

// RemoveGroup removes a group.
func (f *File) RemoveGroup(name string) error {
	if _, ok := f.Group(name); !ok {
		return fmt.Errorf("the group %q does not exist", name)
	}

	var groups []Group
	for _, group := range f.Groups {
		if group.Name != name {
			groups = append(groups, group)
		}
	}
	f.Groups = groups

	mapping := f.section("groups")
	mapping.Content = mappingDelete(mapping.Content, name)
	return nil
}

// section returns the mapping of a section of the file, creating it when it
// does not exist yet.
func (f *File) section(name string) *yaml.Node {
	for i := 0; i+1 < len(f.root.Content); i += 2 {
		if f.root.Content[i].Value == name {
			return f.root.Content[i+1]
		}
	}

	value := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	f.root.Content = append(f.root.Content, scalarNode(name), value)
	return value
}

// scalarNode builds a node with a string value.
func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// machineNode builds the node of a machine.
func machineNode(machine Machine) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	if machine.Label != "" {
		node.Content = append(node.Content,
			scalarNode("label"), scalarNode(machine.Label))
	}

	if len(machine.Hostnames) > 0 {
		hostnames := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, hostname := range machine.Hostnames {
			hostnames.Content = append(hostnames.Content, scalarNode(hostname))
		}
		node.Content = append(node.Content,
			scalarNode("hostnames"), hostnames)
	}

	age := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, key := range machine.Age {
		age.Content = append(age.Content, scalarNode(key))
	}
	node.Content = append(node.Content, scalarNode("age"), age)

	return node
}

// groupNode builds the node of a group.
func groupNode(group Group) *yaml.Node {
	node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, member := range group.Members {
		node.Content = append(node.Content, scalarNode(member))
	}
	return node
}

// mappingDelete removes a key and its value from the content of a mapping.
func mappingDelete(content []*yaml.Node, key string) []*yaml.Node {
	for i := 0; i+1 < len(content); i += 2 {
		if content[i].Value != key {
			continue
		}
		return append(content[:i], content[i+2:]...)
	}
	return content
}
