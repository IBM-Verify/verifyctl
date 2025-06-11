package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	accessPoliciesUsage         = `accesspolicy [flags]`
	accessPoliciesMessagePrefix = "DeleteAccessPolicy"
	accessPoliciesEntitlements  = "Manage accessPolicies"
	accessPolicyResourceName    = "accesspolicy"
)

var (
	accessPoliciesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accessPoliciesMessagePrefix, `
		Delete Verify accessPolicy based on accessPolicyID.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete accesspolicy --entitlements`))

	accessPoliciesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an accessPolicy
		verifyctl delete accesspolicy --ID=accesspolicyID`,
	))
)

type accessPoliciesOptions struct {
	options
	accessPolicyID string
	config         *config.CLIConfig
}

func NewAccessPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &accessPoliciesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   accessPoliciesUsage,
		Short:                 cmdutil.TranslateShortDesc(accessPoliciesMessagePrefix, "Delete Verify accessPolicy based on an id."),
		Long:                  accessPoliciesLongDesc,
		Example:               accessPoliciesExamples,
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

func (o *accessPoliciesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.accessPolicyID, "accessPolicyID", o.accessPolicyID, i18n.Translate("accessPolicyID to be deleted"))
}

func (o *accessPoliciesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accessPoliciesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "accesspolicy" && o.accessPolicyID == "" {
		return errorsx.G11NError("'accessPolicyID' flag is required.")
	}
	return nil
}

func (o *accessPoliciesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+accessPoliciesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "accesspolicy" || len(o.accessPolicyID) > 0 {
		// deal with single accessPolicy
		return o.handleSingleAccessPolicy(cmd, args)
	}
	return nil
}

func (o *accessPoliciesOptions) handleSingleAccessPolicy(cmd *cobra.Command, _ []string) error {

	c := security.NewAccessPolicyClient()
	err := c.DeleteAccessPolicyByID(cmd.Context(), o.accessPolicyID)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.accessPolicyID)
	return nil
}
