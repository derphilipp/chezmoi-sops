// Package groups implements the group model: the discovery of secret groups,
// the recipients registry, and the merge of the groups into one tree.
package groups

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// File names of a group.
const (
	// RecipientsSuffix is the suffix of the recipients file.
	RecipientsSuffix = ".recipients.txt"

	// SOPSPayloadSuffix is the suffix of the sops payload.
	SOPSPayloadSuffix = ".sops.yaml"

	// AgePayloadSuffix is the suffix of the whole-file age payload.
	AgePayloadSuffix = ".yaml.age"
)

// Group is a set of recipients plus a payload.
type Group struct {
	// Name is the group name, which is the file name without the suffixes.
	Name string

	// RecipientsPath is the path of the recipients file.
	RecipientsPath string

	// PayloadPath is the path of the encrypted payload.
	PayloadPath string

	// Format is the payload format of this group.
	Format payload.Payload
}

// Recipients returns the age public keys allowed to decrypt this group.
func (g Group) Recipients() ([]string, error) {
	return readRecipients(g.RecipientsPath)
}

// Registry is the set of groups found in a source directory.
type Registry struct {
	// Dir is the directory the groups were found in.
	Dir string

	// Groups are the groups, sorted by name with "default" first.
	Groups []Group
}

// Names returns the names of the groups, in merge order.
func (r Registry) Names() []string {
	names := make([]string, 0, len(r.Groups))
	for _, g := range r.Groups {
		names = append(names, g.Name)
	}
	return names
}

// Get returns the group with the given name.
func (r Registry) Get(name string) (Group, bool) {
	for _, g := range r.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// Discover finds the groups in dir.
//
// A group is a recipients file plus a payload. The group name is the file
// name without the suffixes, so adding a group means adding its files —
// nothing in a config changes.
//
// The "default" group sorts first, because it is the recipient registry the
// other groups refer to.
func Discover(dir string) (Registry, error) {
	registry := Registry{Dir: dir}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return registry, nil
		}
		return registry, fmt.Errorf("reading %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, RecipientsSuffix) {
			continue
		}

		groupName := strings.TrimSuffix(name, RecipientsSuffix)
		if groupName == "" {
			continue
		}

		group := Group{
			Name:           groupName,
			RecipientsPath: filepath.Join(dir, name),
		}

		// The sops payload wins over the age payload: it is the format
		// that keeps the shape readable.
		sopsPath := filepath.Join(dir, groupName+SOPSPayloadSuffix)
		agePath := filepath.Join(dir, groupName+AgePayloadSuffix)

		switch {
		case fileExists(sopsPath):
			group.PayloadPath = sopsPath
			group.Format = payload.NewSOPS()
		case fileExists(agePath):
			group.PayloadPath = agePath
			group.Format = payload.NewAge()
		default:
			// A recipients file without a payload is not a group yet.
			continue
		}

		registry.Groups = append(registry.Groups, group)
	}

	sortGroups(registry.Groups)
	return registry, nil
}

// sortGroups sorts the groups by name, with "default" first.
func sortGroups(groups []Group) {
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Name == "default" {
			return true
		}
		if groups[j].Name == "default" {
			return false
		}
		return groups[i].Name < groups[j].Name
	})
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// readRecipients reads the recipients of a group.
//
// The format is the one age uses: one recipient per line, comments and blank
// lines ignored.
func readRecipients(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var recipients []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		recipients = append(recipients, line)
	}
	return recipients, nil
}

// HostRegistry maps host names to public keys.
//
// It is built from the "default" group's recipients file, whose comments name
// the machine each key belongs to:
//
//	# laura
//	age1...
//
// The comment is optional; a key without one belongs to no named machine.
type HostRegistry struct {
	// hosts maps a key to the host names that own it.
	hosts map[string][]string
}

// ParseHostRegistry parses a recipients file into a host registry.
func ParseHostRegistry(path string) (HostRegistry, error) {
	registry := HostRegistry{hosts: map[string][]string{}}

	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return registry, nil
		}
		return registry, fmt.Errorf("reading %s: %w", path, err)
	}

	host := ""
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "#"):
			host = strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		default:
			if host != "" {
				registry.hosts[trimmed] = append(registry.hosts[trimmed], host)
			}
		}
	}

	return registry, nil
}

// HostsForKey returns the host names that own the given public key.
func (r HostRegistry) HostsForKey(key string) []string {
	return r.hosts[key]
}

// KeysForHost returns the public keys of a host.
//
// An exact match on the host name wins. Otherwise a prefix match is used,
// which also catches a machine that has several entries.
func (r HostRegistry) KeysForHost(host string) []string {
	want := strings.ToLower(host)

	var exact, prefix []string
	for key, hosts := range r.hosts {
		for _, h := range hosts {
			switch {
			case strings.EqualFold(h, want):
				exact = append(exact, key)
			case strings.HasPrefix(strings.ToLower(h), want):
				prefix = append(prefix, key)
			}
		}
	}

	if len(exact) > 0 {
		sort.Strings(exact)
		return exact
	}
	sort.Strings(prefix)
	return prefix
}
