package cmd

import (
	"io"

	"github.com/spf13/cobra"
	"github.com/vivshankar/verifyctl/pkg/cmd/login"
	"github.com/vivshankar/verifyctl/pkg/config"
	"github.com/vivshankar/verifyctl/pkg/i18n"
)

func NewRootCmd(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	// cmd represents the base command when called without any subcommands
	cmd := &cobra.Command{
		Use:   "verifyctl",
		Short: i18n.Translate("verifyctl controls the IBM Security Verify tenant."),
		Long: i18n.TranslateWithCode(i18n.RootLongDesc, `verifyctl controls the IBM Security Verify tenant.

  Find more information at: https://github.com/vivshankar/verifyctl`),
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	// add commands
	cmd.AddCommand(login.NewCommand(config, streams))

	return cmd
}
