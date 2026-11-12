// Command chezmoi-sops manages sops-encrypted secret groups for chezmoi.
//
// It is a chezmoi plugin: with chezmoi-sops on your PATH, "chezmoi sops"
// runs this program.
package main

import (
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cli.SetVersion(version)

	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
