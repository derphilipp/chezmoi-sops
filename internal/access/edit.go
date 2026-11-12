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

// AddHost adds a machine with its age keys.
func (f *File) AddHost(name string, keys []string) error {
	if _, ok := f.Host(name); ok {
		return fmt.Errorf("the host %q already exists", name)
	}

	host := Host{Name: name, Age: keys}
	f.Hosts = append(f.Hosts, host)

	mapping := f.section("hosts")
	mapping.Content = append(mapping.Content, scalarNode(name), hostNode(host))
	return nil
}

// SetHostKeys replaces the age keys of a machine.
func (f *File) SetHostKeys(name string, keys []string) error {
	host, ok := f.Host(name)
	if !ok {
		return fmt.Errorf("the host %q does not exist", name)
	}

	host.Age = keys
	for i := range f.Hosts {
		if f.Hosts[i].Name == name {
			f.Hosts[i] = host
		}
	}

	mapping := f.section("hosts")
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != name {
			continue
		}
		mapping.Content[i+1] = hostNode(host)
		return nil
	}
	return fmt.Errorf("the host %q does not exist", name)
}

// RemoveHost removes a machine.
func (f *File) RemoveHost(name string) error {
	if _, ok := f.Host(name); !ok {
		return fmt.Errorf("the host %q does not exist", name)
	}

	var hosts []Host
	for _, host := range f.Hosts {
		if host.Name != name {
			hosts = append(hosts, host)
		}
	}
	f.Hosts = hosts

	mapping := f.section("hosts")
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

// hostNode builds the node of a host.
func hostNode(host Host) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	if host.Label != "" {
		node.Content = append(node.Content,
			scalarNode("label"), scalarNode(host.Label))
	}

	if len(host.Hostnames) > 0 {
		hostnames := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, hostname := range host.Hostnames {
			hostnames.Content = append(hostnames.Content, scalarNode(hostname))
		}
		node.Content = append(node.Content,
			scalarNode("hostnames"), hostnames)
	}

	age := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, key := range host.Age {
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
