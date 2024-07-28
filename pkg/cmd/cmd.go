package cmd

import (
	"io"

	"github.com/spf13/cobra"
	"github.com/vivshankar/verifyctl/pkg/cmd/auth"
	"github.com/vivshankar/verifyctl/pkg/cmd/get"
	"github.com/vivshankar/verifyctl/pkg/config"
	cmdutil "github.com/vivshankar/verifyctl/pkg/util/cmd"
	"github.com/vivshankar/verifyctl/pkg/util/templates"
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

  Find more information at: https://github.com/vivshankar/verifyctl`)),
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	// add commands
	cmd.AddCommand(auth.NewCommand(config, streams))
	cmd.AddCommand(get.NewCommand(config, streams))

	return cmd
}
