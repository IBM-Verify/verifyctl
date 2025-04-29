package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	groupsUsage         = `group [flags]`
	groupsMessagePrefix = "DeleteGroup"
	groupsEntitlements  = "Manage groups"
	groupResourceName   = "group"
)

var (
	groupsLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(groupsMessagePrefix, `
		Delete Verify group based on name.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete group --entitlements`))

	groupsExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete a group
		verifyctl delete group --displayName=Sales`,
	))
)

type groupsOptions struct {
	options

	config *config.CLIConfig
}

func NewGroupCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &groupsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   groupsUsage,
		Short:                 cmdutil.TranslateShortDesc(groupsMessagePrefix, "Delete Verify group based on an name."),
		Long:                  groupsLongDesc,
		Example:               groupsExamples,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Valnameate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)

	return cmd
}

func (o *groupsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.name, "displayName", o.name, i18n.Translate("Group displayName to be deleted"))
}

func (o *groupsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *groupsOptions) Valnameate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "group" && o.name == "" {
		return errorsx.G11NError("'displayName' flag is required.")
	}
	return nil
}

func (o *groupsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+groupsEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "group" || len(o.name) > 0 {
		// deal with single group
		return o.handleSingleGroup(cmd, args)
	}
	return nil
}

func (o *groupsOptions) handleSingleGroup(cmd *cobra.Command, _ []string) error {

	c := directory.NewGroupClient()
	err := c.DeleteGroup(cmd.Context(), o.name)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.name)
	return nil
}
