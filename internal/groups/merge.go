package groups

import (
	"fmt"
	"sort"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// Kinds of sources.
const (
	// KindGroup is a group of hosts that may read the same secrets.
	KindGroup = "group"

	// KindHost is a machine with its own secrets.
	KindHost = "host"
)

// Reasons for an unavailable source.
const (
	// ReasonAvailable means the source could be decrypted.
	ReasonAvailable = "available"

	// ReasonNoIdentity means there was no identity to decrypt with.
	ReasonNoIdentity = "no-identity"

	// ReasonNotAuthorized means the identity is not a recipient.
	ReasonNotAuthorized = "not-authorized"

	// ReasonMissing means the payload file is missing.
	ReasonMissing = "missing-payload"
)

// Status describes what happened to one source.
type Status struct {
	// Kind is "group" or "host".
	Kind string `json:"kind"`

	// Name is the name of the group or the host.
	Name string `json:"name"`

	// Available is true when the payload could be decrypted.
	Available bool `json:"available"`

	// Reason explains why the payload could not be decrypted.
	Reason string `json:"reason"`

	// Format is the payload format of the source.
	Format string `json:"format"`

	// Payloads are the payload files of the source.
	Payloads []string `json:"payloads"`

	// Recipients are the age public keys the payloads are encrypted for.
	Recipients []string `json:"recipients"`
}

// Source is one source of secrets: a group or a host.
type Source struct {
	// Kind is "group" or "host".
	Kind string

	// Name is the name of the group or the host.
	Name string

	// Files are the payload files of the source, in merge order.
	Files []string

	// Recipients are the age public keys the payloads are encrypted for.
	Recipients []string

	// Values are the decrypted values of the source.
	Values map[string]any

	// Available is true when the source could be decrypted.
	Available bool

	// Reason explains why not.
	Reason string

	// Format is the payload format of the source.
	Format string

	// Shape is the shape of the source: the key names with empty values.
	Shape map[string]any

	// ContributesShape reports whether the shape of this source is merged
	// when the source cannot be decrypted.
	//
	// A group does: a machine that cannot read a group still renders the
	// templates with empty values. A host does not: its secrets are for
	// that machine alone, so their names belong to it alone too.
	ContributesShape bool
}

// Result is the merged outcome of all sources.
type Result struct {
	// Tree is the merged document: the values this machine can read, with
	// the shapes of the groups it cannot read filling the gaps.
	Tree map[string]any `json:"secrets"`

	// Flat is the tree flattened for the environment: the path is joined
	// with "_" and uppercased, so database.password becomes
	// DATABASE_PASSWORD.
	Flat map[string]string `json:"secretsEnv"`

	// GroupValues are the values of each group, before they were merged.
	GroupValues map[string]map[string]any `json:"secretGroups"`

	// Status is the status of each group.
	Status map[string]Status `json:"secretStatus"`

	// Warnings are the problems found while merging.
	Warnings []string `json:"-"`
}

// Merge combines the sources into one tree.
//
// The order of the sources decides the outcome:
//
//   - the real values are merged first, so the shape of a group this
//     machine cannot read can never shadow a value it can read,
//   - within the real values, the first source that holds a value wins,
//     and the conflict is reported.
//
// The sources are expected in merge order: the groups in the order of the
// access file, then the hosts in the order of the access file.
func Merge(sources []Source) *Result {
	result := &Result{
		Tree:        map[string]any{},
		Flat:        map[string]string{},
		GroupValues: map[string]map[string]any{},
		Status:      map[string]Status{},
	}

	real := map[string]any{}
	shape := map[string]any{}

	// The real values first.
	for _, source := range sources {
		if !source.Available {
			continue
		}
		real = mergeTrees(real, source.Values)

		if source.Kind == KindGroup {
			result.GroupValues[source.Name] = source.Values
		}
	}

	// Then the shapes of the groups this machine cannot read.
	for _, source := range sources {
		if source.Available || !source.ContributesShape {
			continue
		}
		shape = mergeTrees(shape, source.Shape)
	}

	result.Tree = mergeTrees(mergeTrees(map[string]any{}, real), shape)

	// The environment is flattened per source, so a secret of one source
	// does not shadow the flattened name of another.
	flat := map[string]string{}
	origin := map[string]string{}

	for _, source := range sources {
		if !source.Available {
			continue
		}
		for key, value := range flatten(source.Values) {
			if !validEnvName(key) {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"Secret %q (%s %q) does not flatten to a valid environment variable name and is skipped.",
					key, source.Kind, source.Name))
				continue
			}
			if _, ok := flat[key]; ok {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"Secret %q is defined in two sources (%q and %q); keeping the value from %q.",
					key, origin[key], source.Name, origin[key]))
				continue
			}
			flat[key] = value
			origin[key] = source.Name
		}
	}

	result.Flat = flat
	return result
}

// mergeTrees merges src into dst. The values of dst win.
func mergeTrees(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for key, srcValue := range src {
		dstValue, ok := dst[key]
		if !ok {
			dst[key] = srcValue
			continue
		}

		srcMap, srcIsMap := payload.AsMap(srcValue)
		dstMap, dstIsMap := payload.AsMap(dstValue)
		if srcIsMap && dstIsMap {
			dst[key] = mergeTrees(dstMap, srcMap)
		}
		// Otherwise the existing value wins, which is the "first source
		// wins" rule.
	}
	return dst
}

// flatten flattens a tree into environment variable names.
//
// The path is joined with "_" and uppercased. A top-level secret keeps its
// own name.
func flatten(tree map[string]any) map[string]string {
	flat := map[string]string{}
	flattenInto(flat, tree, nil)
	return flat
}

func flattenInto(flat map[string]string, tree map[string]any, path []string) {
	for key, value := range tree {
		current := append(append([]string{}, path...), key)

		if nested, ok := payload.AsMap(value); ok {
			flattenInto(flat, nested, current)
			continue
		}

		switch typed := value.(type) {
		case nil:
			flat[strings.ToUpper(strings.Join(current, "_"))] = ""
		default:
			flat[strings.ToUpper(strings.Join(current, "_"))] = fmt.Sprintf("%v", typed)
		}
	}
}

// validEnvName reports whether name is a valid environment variable name.
func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// SortedNames returns the group names in sorted order.
func SortedNames(names []string) []string {
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	return sorted
}
