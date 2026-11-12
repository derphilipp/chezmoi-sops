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

The groups are merged in a fixed order: "default" first, then the others
alphabetically. The first group wins a conflict, and the conflict is
reported.

A group this machine cannot decrypt still contributes its shape: the key
names with empty values. A template therefore never fails just because a
secret is unavailable, it renders empty instead.

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

	if !quiet {
		for _, warning := range result.Warnings {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
		}
		for name, status := range result.Status {
			if status.Available {
				continue
			}
			fmt.Fprintf(os.Stderr,
				"Warning: the secrets of group %q are not available here (%s). "+
					"This machine is not a recipient of that group, or the payload was "+
					"not re-encrypted after the recipients list changed.\n", name, status.Reason)
		}
	}

	output := map[string]any{
		// The merged tree: the values this machine can read, with the
		// shapes of the groups it cannot read filling the gaps.
		"secrets": result.Tree,
		// The same, flattened for the environment.
		"secretsEnv": result.Flat,
		// The values of each group, before they were merged.
		"secretGroups": result.GroupValues,
		"secretStatus": statusDocument(result),
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fail("Encoding the output: %s", err)
	}
	fmt.Println(string(encoded))

	return nil
}

// statusDocument builds the status part of the output.
func statusDocument(result *groups.Result) map[string]any {
	groupStatus := map[string]any{}
	for name, status := range result.Status {
		groupStatus[name] = map[string]any{
			"available":      status.Available,
			"reason":         status.Reason,
			"format":         status.Format,
			"recipientsFile": status.RecipientsFile,
			"payload":        status.Payload,
		}
	}

	available := false
	for _, status := range result.Status {
		if status.Available {
			available = true
			break
		}
	}

	return map[string]any{
		"available": available,
		"groups":    groupStatus,
	}
}

// merge decrypts every group it can and merges them.
func (e *env) merge() (*groups.Result, error) {
	values := map[string]map[string]any{}
	status := map[string]groups.Status{}

	for _, group := range e.Registry.Groups {
		groupStatus := groups.Status{
			Group:          group.Name,
			Format:         formatOf(group),
			RecipientsFile: group.RecipientsPath,
			Payload:        group.PayloadPath,
		}

		if len(e.Identities) == 0 {
			groupStatus.Reason = groups.ReasonNoIdentity
			status[group.Name] = groupStatus
			values[group.Name] = e.shapeOf(group)
			continue
		}

		raw, err := os.ReadFile(group.PayloadPath)
		if err != nil {
			groupStatus.Reason = groups.ReasonMissing
			status[group.Name] = groupStatus
			values[group.Name] = e.shapeOf(group)
			continue
		}

		decrypted, err := group.Format.Decrypt(cmdContext(), raw, e.Identities)
		if err != nil {
			groupStatus.Reason = groups.ReasonNotAuthorized
			status[group.Name] = groupStatus
			values[group.Name] = e.shapeOf(group)
			continue
		}

		groupStatus.Available = true
		groupStatus.Reason = groups.ReasonAvailable
		status[group.Name] = groupStatus
		values[group.Name] = map[string]any(decrypted)
	}

	return groups.Merge(e.Registry, values, status), nil
}

// shapeOf returns the shape of a group: the key names with empty values.
func (e *env) shapeOf(group groups.Group) map[string]any {
	raw, err := os.ReadFile(group.PayloadPath)
	if err != nil {
		return nil
	}

	shape, err := group.Format.Shape(raw)
	if err != nil {
		// The age format has no shape: without the key there is nothing
		// to show.
		return nil
	}
	return map[string]any(shape)
}
