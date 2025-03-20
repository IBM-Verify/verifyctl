package cmd

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/auth"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/create"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/delete"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/get"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/logs"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/replace"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	messagePrefix   = "Root"
	basicGroupID    = "basic"
	resourceGroupID = "resource"
	debugGroupID    = "debug"
)

func NewRootCmd(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	// cmd represents the base command when called without any subcommands
	cmd := &cobra.Command{
		Use:   "verifyctl",
		Short: cmdutil.TranslateShortDesc(messagePrefix, "verifyctl controls the IBM Security Verify tenant."),
		Long: templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `verifyctl controls the IBM Security Verify tenant.

  Find more information at: https://github.com/ibm-security-verify/verifyctl`)),
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	// add commands
	cmd.AddCommand(auth.NewCommand(config, streams, basicGroupID))
	cmd.AddCommand(get.NewCommand(config, streams, resourceGroupID))
	cmd.AddCommand(create.NewCommand(config, streams, resourceGroupID))
	cmd.AddCommand(replace.NewCommand(config, streams, resourceGroupID))
	cmd.AddCommand(delete.NewCommand(config, streams, resourceGroupID))
	cmd.AddCommand(logs.NewCommand(config, streams, debugGroupID))

	// add groups
	groups := []*cobra.Group{
		{
			ID:    basicGroupID,
			Title: i18n.Translate("Basic Commands"),
		},
		{
			ID:    resourceGroupID,
			Title: i18n.Translate("Configuration Management Commands"),
		},
		{
			ID:    debugGroupID,
			Title: i18n.Translate("Troubleshooting and Debugging Commands"),
		},
	}

	cmd.AddGroup(groups...)

	return cmd
}
