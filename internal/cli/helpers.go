package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
)

// cmdContext returns the context of the current command.
func cmdContext() context.Context {
	return context.Background()
}

// hostRegistry reads the recipient registry: the "default" group, whose
// recipients file names the machine each key belongs to.
func (e *env) hostRegistry() (groups.HostRegistry, error) {
	path := e.Config.SecretsDir() + string(os.PathSeparator) + "default" + groups.RecipientsSuffix
	return groups.ParseHostRegistry(path)
}

// hostKeys returns the public keys of a host.
func (e *env) hostKeys(host string) ([]string, error) {
	registry, err := e.hostRegistry()
	if err != nil {
		return nil, err
	}

	keys := registry.KeysForHost(host)
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"no public key for %q in the recipient registry. Add it to %s",
			host, e.Config.SecretsDir()+string(os.PathSeparator)+"default"+groups.RecipientsSuffix)
	}
	return keys, nil
}
