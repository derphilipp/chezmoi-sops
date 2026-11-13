package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// jsonOutput is the machine-readable output of a command.
type jsonOutput struct {
	// Command is the command that produced the output.
	Command string `json:"command"`

	// OK is false when the command failed.
	OK bool `json:"ok"`

	// Message explains what happened, for the human.
	Message string `json:"message,omitempty"`

	// Groups is the list of groups, for the "groups" command.
	Groups []jsonGroup `json:"groups,omitempty"`

	// Hosts is the list of hosts and the groups they can read, for the
	// "groups" command.
	Hosts []jsonHost `json:"hosts,omitempty"`

	// Removed is the list of files that were removed, for the "delete"
	// command.
	Removed []string `json:"removed,omitempty"`
}

// jsonGroup is one group in the machine-readable output.
type jsonGroup struct {
	// Name is the name of the group.
	Name string `json:"name"`

	// Format is the payload format of the group.
	Format string `json:"format"`

	// Hosts are the machines that can read the group.
	Hosts []string `json:"hosts"`

	// Recipients are the age public keys of the group.
	Recipients []string `json:"recipients"`
}

// jsonHost is one host in the machine-readable output.
type jsonHost struct {
	// Host is the name of the machine.
	Host string `json:"host"`

	// Key is the age public key of the machine.
	Key string `json:"key"`

	// Groups are the groups the machine can read.
	Groups []string `json:"groups,omitempty"`
}

// printJSON writes the machine-readable output of a command.
func printJSON(cmd *cobra.Command, output jsonOutput) error {
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fail("Encoding the output: %s", err)
	}
	cmd.Println(string(encoded))
	return nil
}

// jsonRequested reports whether the --json flag was given.
func jsonRequested(cmd *cobra.Command) bool {
	value, _ := cmd.Flags().GetBool("json")
	return value
}

// addJSONFlag adds the --json flag to a command.
func addJSONFlag(cmd *cobra.Command) {
	cmd.Flags().Bool("json", false, "print the output as JSON")
}

// writeJSONError writes an error as JSON, for the commands that support
// --json.
func writeJSONError(command string, err error) {
	encoded, marshalErr := json.MarshalIndent(jsonOutput{
		Command: command,
		OK:      false,
		Message: err.Error(),
	}, "", "  ")
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return
	}
	fmt.Println(string(encoded))
}
