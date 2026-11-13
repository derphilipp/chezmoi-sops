package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/chezmoi"
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/derphilipp/chezmoi-sops/internal/keyring"
	"github.com/derphilipp/chezmoi-sops/internal/payload"
)

// env is the resolved environment of a command: the chezmoi configuration,
// the layout of the secrets, and the identity.
type env struct {
	// Config is the chezmoi configuration.
	Config chezmoi.Config

	// Layout is the layout of the secrets directory.
	Layout groups.Layout

	// Identities are the age identities of this machine.
	Identities []payload.Identity
}

// ctx returns the context of the current command.
func ctx() context.Context {
	return context.Background()
}

// secretsDir returns the directory the secrets live in.
func (e *env) secretsDir() string {
	return e.Config.SecretsDir()
}

// resolve reads the chezmoi configuration and finds the layout and the
// identity.
func resolve() (*env, error) {
	// The source directory is given when it is known, so the tool works
	// without chezmoi being installed.
	config, err := chezmoi.Load(flagSourceDir)
	if err != nil {
		return nil, err
	}

	layout, err := groups.Discover(config.SecretsDir())
	if err != nil {
		return nil, err
	}

	keys := keyring.Keyring{
		Explicit:   flagIdentity,
		FromConfig: config.Identity,
	}
	identities, err := keys.Find()
	if err != nil {
		// A missing identity is not fatal: a machine without a key still
		// sees the shape of the groups it cannot read.
		identities = nil
	}

	return &env{
		Config:     config,
		Layout:     layout,
		Identities: identities,
	}, nil
}

// sources builds the merge sources: the groups in the order of the access
// file, then the hosts in the order of the access file.
//
// The order decides which value wins when two of them hold the same key.
func (e *env) sources() []groups.Source {
	var sources []groups.Source

	for _, group := range e.Layout.Groups {
		sources = append(sources, e.source(groups.KindGroup, group.Name, group.Dir, group.Recipients, true))
	}

	for _, host := range e.Layout.Hosts {
		sources = append(sources, e.source(groups.KindHost, host.Name, host.Dir, host.Age, false))
	}

	return sources
}

// source builds one merge source and decrypts it if it can.
func (e *env) source(kind, name, dir string, recipients []string, contributesShape bool) groups.Source {
	source := groups.Source{
		Kind:             kind,
		Name:             name,
		Recipients:       recipients,
		ContributesShape: contributesShape,
	}

	files, err := groups.Payloads(dir)
	if err != nil {
		source.Reason = groups.ReasonMissing
		return source
	}
	source.Files = files

	if len(files) == 0 {
		// A source without files is empty, not unreadable.
		source.Available = true
		source.Reason = groups.ReasonAvailable
		source.Values = map[string]any{}
		return source
	}

	source.Format = groups.FormatOf(files[0])

	if len(e.Identities) == 0 {
		source.Reason = groups.ReasonNoIdentity
		source.Shape = e.shapeOf(files)
		return source
	}

	values, err := e.decrypt(files)
	if err != nil {
		source.Reason = groups.ReasonNotAuthorized
		source.Shape = e.shapeOf(files)
		return source
	}

	source.Available = true
	source.Reason = groups.ReasonAvailable
	source.Values = values
	return source
}

// decrypt decrypts the payload files of a source and merges them.
//
// The files are merged in alphabetical order, so the first one that holds a
// value wins.
func (e *env) decrypt(files []string) (map[string]any, error) {
	merged := map[string]any{}

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		values, err := formatOf(file).Decrypt(ctx(), raw, e.Identities)
		if err != nil {
			return nil, err
		}

		merged = mergeDocuments(merged, map[string]any(values))
	}

	return merged, nil
}

// shapeOf returns the shape of the payload files: the key names with empty
// values.
func (e *env) shapeOf(files []string) map[string]any {
	shape := map[string]any{}

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		values, err := formatOf(file).Shape(raw)
		if err != nil {
			// The age format has no shape: without the key there is
			// nothing to show.
			continue
		}
		shape = mergeDocuments(shape, map[string]any(values))
	}

	return shape
}

// formatOf returns the payload format of a file.
func formatOf(path string) payload.Payload {
	if groups.FormatOf(path) == "age" {
		return payload.NewAge()
	}
	return payload.NewSOPS()
}

// mergeDocuments merges src into dst. The values of dst win.
func mergeDocuments(dst, src map[string]any) map[string]any {
	for key, srcValue := range src {
		dstValue, ok := dst[key]
		if !ok {
			dst[key] = srcValue
			continue
		}

		srcMap, srcIsMap := payload.AsMap(srcValue)
		dstMap, dstIsMap := payload.AsMap(dstValue)
		if srcIsMap && dstIsMap {
			dst[key] = mergeDocuments(dstMap, srcMap)
		}
	}
	return dst
}

// merge decrypts every source it can and merges them.
func (e *env) merge() (*groups.Result, error) {
	sources := e.sources()
	result := groups.Merge(sources)

	for _, source := range sources {
		if source.Kind != groups.KindGroup {
			continue
		}
		result.Status[source.Name] = groups.Status{
			Kind:       source.Kind,
			Name:       source.Name,
			Available:  source.Available,
			Reason:     source.Reason,
			Format:     source.Format,
			Payloads:   source.Files,
			Recipients: source.Recipients,
		}
	}

	return result, nil
}

// statusOf returns the availability of the first group, which decides
// whether the secrets are available at all.
//
// The first group is the most general one: it holds the secrets every
// machine is meant to have.
func (e *env) statusOf(sources []groups.Source) (bool, string) {
	for _, source := range sources {
		if source.Kind != groups.KindGroup {
			continue
		}
		return source.Available, source.Reason
	}
	return false, groups.ReasonNoIdentity
}

// groupRecipients returns the recipients of a group.
func (e *env) groupRecipients(name string) ([]string, error) {
	for _, group := range e.Layout.Groups {
		if group.Name == name {
			if len(group.Recipients) == 0 {
				return nil, fmt.Errorf("the group %q has no recipients", name)
			}
			return group.Recipients, nil
		}
	}
	return nil, fmt.Errorf("the group %q does not exist", name)
}

// mustExist reports a readable file, or an error.
func mustExist(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s does not exist", path)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}
