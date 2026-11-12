// Package cli implements the chezmoi-sops command line interface.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// version and commit are the version of the tool and the commit it was
// built from, set at build time.
var (
	version = "dev"
	commit  = ""
)

// SetVersion sets the version of the tool.
func SetVersion(v string) {
	if v == "" {
		return
	}
	version = v
	rootCmd.Version = VersionString()
}

// SetCommit sets the commit the tool was built from.
func SetCommit(c string) {
	if c == "" {
		return
	}
	commit = c
	rootCmd.Version = VersionString()
}

// VersionString returns the version of the tool, with the commit it was
// built from.
//
// The commit is left out when the version already carries it: the
// pseudo-version of a source install ends with the commit.
func VersionString() string {
	if commit == "" {
		return version
	}

	// Some version formats already carry the commit: the pseudo-version
	// of a source install ends with it, and "git describe" puts it in
	// there as "-g<commit>".
	if strings.Contains(version, shortCommit(commit)) {
		return version
	}

	return fmt.Sprintf("%s (commit %s)", version, shortCommit(commit))
}

// shortCommit shortens a commit hash to the seven characters that identify
// it.
func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

// Global options, shared by every subcommand.
var (
	flagSourceDir  string
	flagIdentity   string
	flagRecipients string
	flagEditor     string
)

var rootCmd = &cobra.Command{
	Use:   "chezmoi-sops",
	Short: "Manage sops-encrypted secret groups for chezmoi",
	Long: `chezmoi-sops manages secret groups for chezmoi.

A group is a set of recipients plus a payload:

  .secrets/<group>.recipients.txt   the age public keys allowed to decrypt it
  .secrets/<group>.sops.yaml        the payload, sops encrypted
  .secrets/<group>.yaml.age         the payload, whole-file age encrypted

Because sops encrypts only the values, the key names stay readable in the
repository. A machine that cannot decrypt a group still sees its shape, so
templates render with empty values instead of failing.

The identity comes from chezmoi's own configuration, so a machine is
configured in exactly one place.

It runs as a chezmoi plugin: put chezmoi-sops on your PATH and use
"chezmoi sops ...".`,
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagSourceDir, "source-dir", "",
		"chezmoi source directory (default: chezmoi source-path)")
	rootCmd.PersistentFlags().StringVar(&flagIdentity, "identity", "",
		"age identity file (default: chezmoi's configuration)")
	rootCmd.PersistentFlags().StringVar(&flagRecipients, "recipients", "",
		"age recipients file (default: the group's own recipients file)")
	rootCmd.PersistentFlags().StringVar(&flagEditor, "editor", "",
		"editor to use (default: $VISUAL, then $EDITOR)")
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		// The quiet error means the command already reported the problem.
		if !errors.Is(err, errQuiet) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		return err
	}
	return nil
}

// errQuiet is returned by commands that already reported the problem.
var errQuiet = errors.New("")

// fail prints a message and returns the quiet error, so the command exits
// with a non-zero status without printing the message twice.
func fail(format string, args ...any) error {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	return errQuiet
}

func init() {
	rootCmd.AddCommand(
		newEditCmd(),
		newNewCmd(),
		newGroupsCmd(),
		newDeleteCmd(),
		newDataCmd(),
		newDoctorCmd(),
		newMembersCmd(),
		newKeysCmd(),
		newRenameCmd(),
		newSyncCmd(),
		newHostsCmd(),
		newMigrateCmd(),
	)
}
