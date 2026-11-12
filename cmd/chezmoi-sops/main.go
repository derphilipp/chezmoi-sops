// Command chezmoi-sops manages sops-encrypted secret groups for chezmoi.
//
// It is a chezmoi plugin: with chezmoi-secrets on your PATH, "chezmoi sops"
// runs this program.
package main

import (
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
