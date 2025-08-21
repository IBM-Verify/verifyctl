package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	identitySourcesUsage         = `identitysource [flags]`
	identitySourcesMessagePrefix = "DeleteIdentitySource"
	identitySourcesEntitlements  = "Manage identitySources"
	identitySourceResourceName   = "identitysource"
)

var (
	identitySourcesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitySourcesMessagePrefix, `
		Delete Verify identitySource based on identitySourceID.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete identitysource --entitlements`))

	identitySourcesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an identitySource
		verifyctl delete identitysource --identitySource "identitySourceID"`,
	))
)

type identitySourcesOptions struct {
	options
	identitySourceID string
	config           *config.CLIConfig
}

func NewIdentitySourceCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identitySourcesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identitySourcesUsage,
		Short:                 cmdutil.TranslateShortDesc(identitySourcesMessagePrefix, "Delete Verify identitySource based on an id."),
		Long:                  identitySourcesLongDesc,
		Example:               identitySourcesExamples,
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

func (o *identitySourcesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.identitySourceID, "identitySourceID", o.identitySourceID, i18n.Translate("identitySourceID to be deleted"))
}

func (o *identitySourcesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitySourcesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "identitysource" && o.identitySourceID == "" {
		return errorsx.G11NError("'identitySourceID' flag is required.")
	}
	return nil
}

func (o *identitySourcesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identitySourcesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "identitysource" || len(o.identitySourceID) > 0 {
		return o.handleSingleIdentitySource(cmd, args)
	}
	return nil
}

func (o *identitySourcesOptions) handleSingleIdentitySource(cmd *cobra.Command, _ []string) error {

	c := authentication.NewIdentitySourceClient()
	err := c.DeleteIdentitySourceByID(cmd.Context(), o.identitySourceID)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.identitySourceID)
	return nil
}
