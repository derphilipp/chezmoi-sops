// Command chezmoi-sops manages sops-encrypted secret groups for chezmoi.
//
// It is a chezmoi plugin: with chezmoi-sops on your PATH, "chezmoi sops"
// runs this program.
package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/derphilipp/chezmoi-sops/internal/cli"
)

// version and commit are set at build time with
// -ldflags "-X main.version=... -X main.commit=...".
//
// A binary that was installed with "go install" has no such flags, so the
// version is taken from the build information instead.
var (
	version = "dev"
	commit  = ""
)

func main() {
	cli.SetVersion(buildVersion())
	cli.SetCommit(buildCommit())

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
	if version != "dev" {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return version
}

// buildCommit returns the commit the tool was built from.
//
// A source install has no commit flag, but the pseudo-version of
// "go install" ends with the commit it was built from.
func buildCommit() string {
	if commit != "" {
		return commit
	}

	v := buildVersion()
	index := strings.LastIndex(v, "-")
	if index < 0 {
		return ""
	}

	hash := v[index+1:]
	if len(hash) < 7 || !isHex(hash) {
		return ""
	}
	return hash
}

// isHex reports whether s is a hexadecimal string.
func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
