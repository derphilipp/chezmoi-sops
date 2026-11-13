package cli

import (
	"path/filepath"

	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/spf13/cobra"
)

// completeGroups completes the names of the groups.
func completeGroups(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var candidates []string
	for _, group := range environment.Layout.Groups {
		candidates = append(candidates, group.Name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}

// completeMachines completes the names of the machines.
func completeMachines(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var candidates []string
	for _, machine := range environment.Layout.Machines {
		candidates = append(candidates, machine.Name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}

// completeGroupMachines completes the name of a group and then the names of
// the machines.
//
// It is used by the commands that take a group and the machines that may
// read it.
func completeGroupMachines(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return completeGroups(cmd, args, toComplete)
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var candidates []string
	for _, machine := range environment.Layout.Machines {
		candidates = append(candidates, machine.Name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}

// completeNewGroup completes the machines of a group that is being created.
//
// The name of the group does not exist yet, so only the machines are
// completed.
func completeNewGroup(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var candidates []string
	for _, machine := range environment.Layout.Machines {
		candidates = append(candidates, machine.Name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}

// completeGroupTarget completes the name of a group and then the payload
// files inside it.
func completeGroupTarget(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	switch len(args) {
	case 0:
		return completeGroups(cmd, args, toComplete)
	case 1:
		return completePayloadFiles(cmd, args, toComplete, kindGroup)
	default:
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeMachineTarget completes the name of a machine and then the
// payload files inside it.
func completeMachineTarget(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	switch len(args) {
	case 0:
		return completeMachines(cmd, args, toComplete)
	case 1:
		return completePayloadFiles(cmd, args, toComplete, kindMachine)
	default:
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

// completePayloadFiles completes the payload files of a group or a machine.
//
// The group or the machine is the first argument, the file is the second.
func completePayloadFiles(cmd *cobra.Command, args []string, toComplete string, kind string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	dir, _, err := environment.targetDir(target{Kind: kind, Name: args[0]})
	if err != nil || dir == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	files, err := groups.Payloads(dir)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var candidates []string
	for _, file := range files {
		candidates = append(candidates, filepath.Base(file))
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}
