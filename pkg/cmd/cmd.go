package cmd

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/auth"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/get"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	messagePrefix = "Root"
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
	cmd.AddCommand(auth.NewCommand(config, streams))
	cmd.AddCommand(get.NewCommand(config, streams))

	return cmd
}
