package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/access"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"gopkg.in/yaml.v3"
)

// accessPath returns the path of the access file.
func (e *env) accessPath() string {
	return e.secretsDir() + string(os.PathSeparator) + access.FileName
}

// addGroup adds a group to the access file.
func (e *env) addGroup(name string, members []string) error {
	for _, member := range members {
		if _, ok := e.Layout.Access.Host(member); !ok {
			return fmt.Errorf("the host %q is not in %s", member, access.FileName)
		}
	}

	return e.rewriteAccess(func(file *access.File) {
		file.Groups = append(file.Groups, access.Group{Name: name, Members: members})
	})
}

// addHost adds a host to the access file.
func (e *env) addHost(name string, keys []string) error {
	return e.rewriteAccess(func(file *access.File) {
		file.Hosts = append(file.Hosts, access.Host{Name: name, Age: keys})
	})
}

// removeEntry removes a group or a host from the access file.
func (e *env) removeEntry(t target) error {
	return e.rewriteAccess(func(file *access.File) {
		switch t.Kind {
		case groups.KindGroup:
			var groups []access.Group
			for _, group := range file.Groups {
				if group.Name != t.Name {
					groups = append(groups, group)
				}
			}
			file.Groups = groups
		case groups.KindHost:
			var hosts []access.Host
			for _, host := range file.Hosts {
				if host.Name != t.Name {
					hosts = append(hosts, host)
				}
			}
			file.Hosts = hosts
		}
	})
}

// rewriteAccess applies a change to the access file and writes it back.
//
// The file is read as an ordered document, so the order of the hosts and
// groups is preserved: it decides which value wins.
func (e *env) rewriteAccess(change func(*access.File)) error {
	path := e.accessPath()

	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	file, err := access.Load(path)
	if err != nil {
		return err
	}
	change(file)

	// The order of the hosts and the groups is the order of the file, so
	// the rewritten document is rebuilt from the parsed one.
	if err := writeAccess(path, file); err != nil {
		return err
	}

	return nil
}

// writeAccess writes the access file.
//
// The file is written by hand rather than through the YAML marshaller, so
// the comments in it survive.
func writeAccess(path string, file *access.File) error {
	var out strings.Builder

	out.WriteString("# The machines that have an age identity, and the groups of secrets\n")
	out.WriteString("# they may read.\n")
	out.WriteString("#\n")
	out.WriteString("# The order matters: the groups are merged in this order, and the first\n")
	out.WriteString("# one that holds a value wins.\n")

	out.WriteString("hosts:\n")
	for _, host := range file.Hosts {
		fmt.Fprintf(&out, "  %s:\n", host.Name)
		if host.Label != "" {
			fmt.Fprintf(&out, "    label: %q\n", host.Label)
		}
		if len(host.Hostnames) > 0 {
			out.WriteString("    hostnames:\n")
			for _, hostname := range host.Hostnames {
				fmt.Fprintf(&out, "      - %s\n", hostname)
			}
		}
		out.WriteString("    age:\n")
		for _, key := range host.Age {
			fmt.Fprintf(&out, "      - %s\n", key)
		}
	}

	out.WriteString("groups:\n")
	for _, group := range file.Groups {
		fmt.Fprintf(&out, "  %s:\n", group.Name)
		for _, member := range group.Members {
			fmt.Fprintf(&out, "    - %s\n", member)
		}
	}

	return os.WriteFile(path, []byte(out.String()), 0o600)
}
