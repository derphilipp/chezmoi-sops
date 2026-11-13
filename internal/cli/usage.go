package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// usageError reports that the command was called in a way that cannot work,
// by printing what it needs and how it is used.
//
// The error is quiet: the message is already printed, so the caller exits
// with a non-zero status without printing it again. The hint says what was
// missing; the usage comes from the command itself, so it cannot drift away
// from the flags the command really has.
func usageError(cmd *cobra.Command, hint string) error {
	fmt.Fprintln(cmd.ErrOrStderr(), hint)
	fmt.Fprintln(cmd.ErrOrStderr())
	fmt.Fprint(cmd.ErrOrStderr(), cmd.UsageString())
	return errQuiet
}

// exactArgs is cobra.ExactArgs with a message that says what is missing.
//
// Cobra's own message is "accepts 1 arg(s), received 0", which tells the
// user nothing about what the argument should be.
func exactArgs(count int, hint string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == count {
			return nil
		}
		return usageError(cmd, hint)
	}
}

// rangeArgs is cobra.RangeArgs with a message that says what is missing.
func rangeArgs(minimum, maximum int, hint string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) >= minimum && len(args) <= maximum {
			return nil
		}
		return usageError(cmd, hint)
	}
}

// minArgs is cobra.MinimumNArgs with a message that says what is missing.
func minArgs(minimum int, hint string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) >= minimum {
			return nil
		}
		return usageError(cmd, hint)
	}
}

// noArgs is cobra.NoArgs with a message that says what is wrong.
//
// Cobra's own message is "unknown command %q for %q", which reads as though
// the command does not exist, when it is the extra argument that is the
// problem.
func noArgs(hint string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		return usageError(cmd, hint)
	}
}
