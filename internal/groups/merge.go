package groups

import (
	"fmt"
	"sort"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// Status describes what happened to one group.
type Status struct {
	// Group is the name of the group.
	Group string

	// Available is true when the group could be decrypted.
	Available bool

	// Reason explains why the group is not available.
	Reason string

	// Format is the payload format of the group.
	Format string

	// RecipientsFile is the path of the recipients file.
	RecipientsFile string

	// Payload is the path of the encrypted payload.
	Payload string
}

// Reasons for an unavailable group.
const (
	ReasonAvailable     = "available"
	ReasonNoIdentity    = "no-identity"
	ReasonNotAuthorized = "not-authorized"
	ReasonMissing       = "missing-payload"
	ReasonNoShape       = "no-shape"
)

// Result is the merged outcome of all groups.
type Result struct {
	// Tree is the merged document: the real values, with the shapes of the
	// unreadable groups filling the gaps.
	Tree map[string]any

	// Flat is the tree flattened for the environment: the path is joined
	// with "_" and uppercased, so database.password becomes
	// DATABASE_PASSWORD.
	Flat map[string]string

	// Status is the per-group status.
	Status map[string]Status

	// GroupValues are the values of each group, before they were merged.
	GroupValues map[string]map[string]any

	// Warnings are the problems found while merging.
	Warnings []string
}

// Merge combines the groups into one tree.
//
// The order matters and matches the behaviour of the existing template:
//
//   - real values are merged first, so the shape of an unreadable group can
//     never shadow a value this machine is allowed to read,
//   - the first group wins a conflict, and the conflict is reported.
//
// The groups are merged in the order of the registry: "default" first, then
// the others alphabetically.
func Merge(registry Registry, values map[string]map[string]any, status map[string]Status) *Result {
	result := &Result{
		Tree:        map[string]any{},
		Flat:        map[string]string{},
		Status:      status,
		GroupValues: values,
	}

	real := map[string]any{}
	shape := map[string]any{}

	var realGroups, shapeGroups []string

	for _, group := range registry.Groups {
		values, ok := values[group.Name]
		if !ok {
			continue
		}

		if status[group.Name].Available {
			real = mergeTrees(real, values)
			realGroups = append(realGroups, group.Name)
		} else {
			shape = mergeTrees(shape, values)
			shapeGroups = append(shapeGroups, group.Name)
		}
	}

	result.Tree = mergeTrees(mergeTrees(map[string]any{}, real), shape)

	// The environment is flattened in two passes as well: the real values
	// first, so a shape cannot shadow them either.
	flat := map[string]string{}
	origin := map[string]string{}

	for _, phase := range []struct {
		real   bool
		groups []string
	}{{true, realGroups}, {false, shapeGroups}} {
		for _, name := range phase.groups {
			values := values[name]
			if values == nil {
				continue
			}
			for key, value := range flatten(values) {
				if !validEnvName(key) {
					result.Warnings = append(result.Warnings, fmt.Sprintf(
						"Secret %q (group %q) does not flatten to a valid environment variable name and is skipped.",
						key, name))
					continue
				}
				if _, ok := flat[key]; ok {
					if phase.real {
						result.Warnings = append(result.Warnings, fmt.Sprintf(
							"Secret %q is defined in two groups (%q and %q); keeping the value from group %q.",
							key, origin[key], name, origin[key]))
					}
					continue
				}
				flat[key] = value
				origin[key] = name
			}
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
		// Otherwise the existing value wins, which is the "first group
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
func SortedNames(registry Registry) []string {
	names := registry.Names()
	sort.Strings(names)
	return names
}
