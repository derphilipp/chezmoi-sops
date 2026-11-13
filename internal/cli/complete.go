package cli

import (
	"github.com/derphilipp/chezmoi-sops/internal/groups"
	"github.com/spf13/cobra"
)

// completeTargets completes the group and the host names.
//
// The target of a command is written as "group/<name>" or "host/<name>", so
// both are offered.
func completeTargets(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var candidates []string
	for _, group := range environment.Layout.Groups {
		candidates = append(candidates, groups.KindGroup+"/"+group.Name)
	}
	for _, host := range environment.Layout.Hosts {
		candidates = append(candidates, groups.KindHost+"/"+host.Name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}

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

// completeHosts completes the names of the machines.
func completeHosts(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	environment, err := resolve()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var candidates []string
	for _, host := range environment.Layout.Hosts {
		candidates = append(candidates, host.Name)
	}

	return candidates, cobra.ShellCompDirectiveNoFileComp
}
