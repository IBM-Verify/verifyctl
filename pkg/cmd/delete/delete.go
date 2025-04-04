package delete

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usage         = "delete [resource-type] --name=name"
	messagePrefix = "Delete"
)

var (
	shortDesc = cmdutil.TranslateShortDesc(messagePrefix, "Delete a Verify resource.")

	longDesc = templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `
		Delete a Verify resource.

Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete [resource-type] --entitlements

Certain resources may offer additional options and can be determined using:

  verifyctl delete [resource-type] -h`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an user
		verifyctl delete user --userName=userName`))

	entitlementsMessage = i18n.Translate("Choose any of the following entitlements to configure your application or API client:\n")
)

type options struct {
	entitlements bool
	name         string
	config       *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter, groupID string) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 shortDesc,
		Long:                  longDesc,
		Example:               examples,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
		GroupID: groupID,
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	// add sub commands
	cmd.AddCommand(NewUserCommand(config, streams))
	cmd.AddCommand(NewGroupCommand(config, streams))
	cmd.AddCommand(NewAPIclientCommand(config, streams))

	return cmd
}

func (o *options) addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.entitlements, "entitlements", o.entitlements, i18n.Translate("List the entitlements that can be configured to grant access to the resource. This is useful to know what to configure on the application or API client used to generate the login token. When this flag is used, the others are ignored."))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	return nil
}
