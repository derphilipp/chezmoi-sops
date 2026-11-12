// Command chezmoi-sops manages sops-encrypted secret groups for chezmoi.
//
// It is a chezmoi plugin: with chezmoi-sops on your PATH, "chezmoi sops"
// runs this program.
package main

import (
	"os"
	"runtime/debug"

	"github.com/derphilipp/chezmoi-sops/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
//
// A binary that was installed with "go install" has no such flag, so the
// version is taken from the build information instead.
var version = "dev"

func main() {
	cli.SetVersion(buildVersion())

	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildVersion returns the version of the tool.
//
// The build information is preferred over the flag when it has a version:
// "go install" records the version it installed in it, so a tool installed
// that way knows which version it is.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}

	if version != "dev" {
		return version
	}

	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return version
}
