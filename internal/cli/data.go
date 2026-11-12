package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/spf13/cobra"
)

func newDataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "data",
		Short: "Print the merged secrets for the chezmoi templates",
		Long: `Print the merged secrets for the chezmoi templates.

The groups are merged in the order of the access file, then the hosts. The
first source that holds a value wins, and the conflict is reported.

A group this machine cannot decrypt still contributes its shape: the key
names with empty values. A template therefore never fails just because a
secret is unavailable, it renders empty instead. The secrets of a host are
for that machine alone, so they contribute nothing to any other machine.

The output is a JSON object:

  {
    "secrets":      { "TOKEN": "value" },       the merged tree
    "secretsEnv":   { "TOKEN": "value" },       the merged tree, flattened
    "secretGroups": { "default": { ... } },     the values of each group
    "secretStatus": { "available": true },      the status of the groups
  }`,
		Args: cobra.NoArgs,
		RunE: runData,
	}
	cmd.Flags().String("format", "json", "output format (json)")
	cmd.Flags().Bool("quiet", false, "do not print warnings to stderr")
	return cmd
}

func runData(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	if format != "json" {
		return fail("Unknown output format %q, only \"json\" is supported.", format)
	}
	quiet, _ := cmd.Flags().GetBool("quiet")

	environment, err := resolve()
	if err != nil {
		return err
	}

	result, err := environment.merge()
	if err != nil {
		return err
	}

	sources := environment.sources()

	if !quiet {
		if len(environment.Identities) == 0 {
			fmt.Fprintln(os.Stderr,
				"Warning: no age identity was found, so nothing could be decrypted. "+
					"Restore an authorized key, or run 'chezmoi sops doctor' to see what was looked at.")
		}
		for _, warning := range result.Warnings {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
		}
		for _, source := range sources {
			if source.Kind != groups.KindGroup || source.Available {
				continue
			}
			fmt.Fprintf(os.Stderr,
				"Warning: the secrets of group %q are not available here (%s). "+
					"This machine is not a recipient of that group, or the payload was "+
					"not re-encrypted after the recipients list changed.\n", source.Name, source.Reason)
		}
	}

	available, reason := environment.statusOf(sources)

	output := map[string]any{
		// The merged tree: the values this machine can read, with the
		// shapes of the groups it cannot read filling the gaps.
		"secrets": result.Tree,
		// The same, flattened for the environment.
		"secretsEnv": result.Flat,
		// The values of each group, before they were merged.
		"secretGroups": result.GroupValues,
		"secretStatus": statusDocument(result, available, reason),
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fail("Encoding the output: %s", err)
	}
	fmt.Println(string(encoded))

	return nil
}

// statusDocument builds the status part of the output.
//
// The top level mirrors the first group, which is the most general one: it
// holds the secrets every machine is meant to have, so its status is the
// status of the whole set.
func statusDocument(result *groups.Result, available bool, reason string) map[string]any {
	groupStatus := map[string]any{}
	for name, status := range result.Status {
		groupStatus[name] = map[string]any{
			"available":      status.Available,
			"reason":         status.Reason,
			"format":         status.Format,
			"payloads":       status.Payloads,
			"recipientsFile": status.Recipients,
		}
	}

	return map[string]any{
		"available": available,
		"reason":    reason,
		"groups":    groupStatus,
	}
}
