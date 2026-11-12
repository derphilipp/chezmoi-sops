package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/spf13/cobra"
)

// outOfSync describes a payload that was not encrypted again after its
// group changed.
type outOfSync struct {
	// Name is the name of the group.
	Name string

	// File is the payload file.
	File string

	// Missing are the recipients the payload should have but does not.
	Missing []string

	// Extra are the recipients the payload has but should not.
	Extra []string
}

// checkGroups reports the groups whose payload is not encrypted for the
// recipients their members have.
//
// A payload is encrypted for a fixed set of keys. When the members of a
// group change, the payload has to be encrypted again, or the new members
// cannot read it and the removed ones still can.
func (e *env) checkGroups() []outOfSync {
	var problems []outOfSync

	for _, group := range e.Layout.Groups {
		files, err := groups.Payloads(group.Dir)
		if err != nil {
			continue
		}

		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				continue
			}

			encryptedFor, err := formatOf(file).Recipients(raw)
			if err != nil || len(encryptedFor) == 0 {
				// The format cannot tell, so there is nothing to
				// compare.
				continue
			}

			problem := outOfSync{Name: group.Name, File: file}

			want := map[string]bool{}
			for _, recipient := range group.Recipients {
				want[recipient] = true
			}
			have := map[string]bool{}
			for _, recipient := range encryptedFor {
				have[recipient] = true
			}

			for recipient := range want {
				if !have[recipient] {
					problem.Missing = append(problem.Missing, recipient)
				}
			}
			for recipient := range have {
				if !want[recipient] {
					problem.Extra = append(problem.Extra, recipient)
				}
			}

			if len(problem.Missing) == 0 && len(problem.Extra) == 0 {
				continue
			}

			sort.Strings(problem.Missing)
			sort.Strings(problem.Extra)
			problems = append(problems, problem)
		}
	}

	return problems
}

// describe returns a one-line description of the problem.
func (p outOfSync) describe() string {
	switch {
	case len(p.Missing) > 0 && len(p.Extra) > 0:
		return fmt.Sprintf("%d key(s) missing, %d key(s) that should not be there",
			len(p.Missing), len(p.Extra))
	case len(p.Missing) > 0:
		return fmt.Sprintf("%d key(s) missing: the new members cannot read it yet", len(p.Missing))
	default:
		return fmt.Sprintf("%d key(s) that should not be there: the removed members can still read it",
			len(p.Extra))
	}
}

// fix returns the command that brings the payload back in line.
func (p outOfSync) fix() string {
	return fmt.Sprintf("chezmoi sops sync")
}

func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Encrypt the payloads again for the current members",
		Long: `Encrypt the payloads again for the current members.

A payload is encrypted for a fixed set of keys. When the members of a group
change, the payload has to be encrypted again: otherwise the new members
cannot read it, and the removed ones still can.

This finds the payloads that are out of date and encrypts them again. It
needs the identity of a machine that can read them, so a payload this
machine cannot read is reported instead of being changed.`,
		Args: cobra.NoArgs,
		RunE: runSync,
	}
	cmd.Flags().Bool("check", false, "only report what is out of date, change nothing")
	addJSONFlag(cmd)
	return cmd
}

func runSync(cmd *cobra.Command, args []string) error {
	check, _ := cmd.Flags().GetBool("check")

	environment, err := resolve()
	if err != nil {
		return err
	}

	problems := environment.checkGroups()
	if len(problems) == 0 {
		if jsonRequested(cmd) {
			return printJSON(jsonOutput{
				Command: "sync",
				OK:      true,
				Message: "Every payload is encrypted for the current members.",
			})
		}
		fmt.Println("Every payload is encrypted for the current members.")
		return nil
	}

	var synced []string
	var failed []string

	for _, problem := range problems {
		if check {
			continue
		}

		recipients, err := environment.newRecipients(problem.Name)
		if err != nil {
			failed = append(failed, problem.Name)
			continue
		}

		if _, err := environment.reencryptGroup(problem.Name, recipients); err != nil {
			failed = append(failed, problem.Name)
			continue
		}
		synced = append(synced, problem.Name)
	}

	if jsonRequested(cmd) {
		output := jsonOutput{
			Command: "sync",
			OK:      len(failed) == 0,
			Message: fmt.Sprintf("%d payload(s) were out of date.", len(problems)),
		}
		for _, problem := range problems {
			output.Groups = append(output.Groups, jsonGroup{
				Name:  problem.Name,
				Hosts: problem.Missing,
			})
		}
		if err := printJSON(output); err != nil {
			return err
		}
		if len(failed) > 0 {
			return fail("The payloads of %v could not be encrypted again.", failed)
		}
		return nil
	}

	for _, problem := range problems {
		fmt.Printf("%s: %s\n", problem.Name, problem.describe())
	}

	switch {
	case check:
		fmt.Printf("\nRun 'chezmoi sops sync' to encrypt them again.\n")
	case len(failed) > 0:
		return fail("The payloads of %v could not be encrypted again. "+
			"A machine that can read them has to do it.", failed)
	default:
		fmt.Printf("\nEncrypted %d payload(s) again for the current members.\n", len(synced))
	}

	return nil
}
