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
	passwordPolicyUsage         = "passwordpolicy [options]"
	passwordPolicyMessagePrefix = "DeletePasswordPolicy"
	passwordPolicyEntitlements  = "Manage password policies"
	passwordPolicyResourceName  = "passwordpolicy"
)

var (
	passwordPolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(passwordPolicyMessagePrefix, `
Delete a password policy in IBM Security Verify based on policy passwordPolicyID.
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.
You can identify the entitlement required by running:

verifyctl delete passwordpolicy --entitlements`))

	passwordPolicyExamples = templates.Examples(cmdutil.TranslateExamples(passwordPolicyMessagePrefix, `
# Delete a password policy by passwordPolicyID
verifyctl delete passwordpolicy --passwordPolicyID=passwordPolicyID
`))
)

type passwordPolicyOptions struct {
	options
	passwordPolicyID string
	config           *config.CLIConfig
}

func NewPasswordPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &passwordPolicyOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   passwordPolicyUsage,
		Short:                 cmdutil.TranslateShortDesc(passwordPolicyMessagePrefix, "Delete Verify password policy based on passwordPolicyID."),
		Long:                  passwordPolicyLongDesc,
		Example:               passwordPolicyExamples,
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

func (o *passwordPolicyOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.passwordPolicyID, "passwordPolicyID", o.passwordPolicyID, i18n.Translate("Identifier of the password policy to delete. (Required)"))
}

func (o *passwordPolicyOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *passwordPolicyOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}
	calledAs := cmd.CalledAs()
	if calledAs == "passwordpolicy" && o.passwordPolicyID == "" {
		return errorsx.G11NError(i18n.Translate("The 'passwordPolicyID' flag is required to delete a password policy"))
	}
	return nil
}

func (o *passwordPolicyOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+passwordPolicyEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}
	if cmd.CalledAs() == "passwordpolicy" || len(o.passwordPolicyID) > 0 {

		return o.handleSinglePasswordPolicy(cmd, args)
	}
	return nil
}
func (o *passwordPolicyOptions) handleSinglePasswordPolicy(cmd *cobra.Command, _ []string) error {

	c := security.NewPasswordPolicyClient()
	err := c.DeletePasswordPolicyByID(cmd.Context(), o.passwordPolicyID)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.passwordPolicyID)
	return nil
}
