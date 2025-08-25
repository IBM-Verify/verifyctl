package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/applications"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	applicationUsage         = "application [options]"
	applicationMessagePrefix = "DeleteApplication"
	applicationEntitlements  = "Manage applications"
	applicationResourceName  = "application"
)

var (
	applicationLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(applicationMessagePrefix, `
		Delete Verify Application based on ApplicationID.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete application --entitlements`))

	applicationExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an Application
		verifyctl delete application --applicationID "applicationID"`,
	))
)

type applicationsOptions struct {
	options
	applicationID string
	config        *config.CLIConfig
}

func NewApplicationCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &applicationsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   applicationUsage,
		Short:                 cmdutil.TranslateShortDesc(applicationMessagePrefix, "Delete Verify Application based on an application ID."),
		Long:                  applicationLongDesc,
		Example:               applicationExamples,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)

	return cmd
}

func (o *applicationsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.applicationID, "applicationID", o.applicationID, i18n.Translate("applicationID to be deleted"))
}

func (o *applicationsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *applicationsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "application" && o.applicationID == "" {
		return errorsx.G11NError(i18n.Translate("'applicationID' flag is required"))
	}
	return nil
}

func (o *applicationsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+applicationEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}
	if cmd.CalledAs() == "application" || len(o.applicationID) > 0 {

		return o.handleSingleApplication(cmd, args)
	}
	return nil
}

func (o *applicationsOptions) handleSingleApplication(cmd *cobra.Command, _ []string) error {

	c := applications.NewApplicationClient()
	err := c.DeleteApplicationByID(cmd.Context(), o.applicationID)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.applicationID)
	return nil
}
