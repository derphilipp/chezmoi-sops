// Package cli implements the chezmoi-sops command line interface.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

// ErrNotImplemented is returned by commands whose logic lands in a later
// phase. It exists so the command surface can be reviewed before the
// behaviour is.
var ErrNotImplemented = errors.New("not implemented yet")

// Global options, shared by every subcommand.
var (
	flagSourceDir string
	flagIdentity  string
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

It runs as a chezmoi plugin: put chezmoi-secrets on your PATH and use
"chezmoi sops ...".`,
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagSourceDir, "source-dir", "",
		"chezmoi source directory (default: chezmoi source-path)")
	rootCmd.PersistentFlags().StringVar(&flagIdentity, "identity", "",
		"age identity file (default: discovered)")
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return err
	}
	return nil
}

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit [group]",
		Short: "Decrypt a group, open it in the editor, and re-encrypt it",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrNotImplemented
		},
	}
	cmd.Flags().BoolP("force", "f", false, "overwrite without decrypting first")
	cmd.Flags().String("sops", "", "convert the group to the sops format")
	cmd.Flags().String("age", "", "convert the group to the age format")
	return cmd
}

func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <name> [recipient ...]",
		Short: "Create a secret group",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrNotImplemented
		},
	}
	cmd.Flags().Bool("per-host", false, "create one group per host")
	cmd.Flags().String("suffix", "", "suffix for --per-host group names")
	return cmd
}

func newGroupsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "groups",
		Short: "Show which machines are in which group",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrNotImplemented
		},
	}
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <group>",
		Short: "Remove a secret group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrNotImplemented
		},
	}
}

func init() {
	rootCmd.AddCommand(newEditCmd(), newNewCmd(), newGroupsCmd(), newDeleteCmd())
}
