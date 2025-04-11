package delete

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/security"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	accesspoliciesUsage         = `accesspolicy [flags]`
	accesspoliciesMessagePrefix = "DeleteAccessPolicy"
	accesspoliciesEntitlements  = "Manage accesspolicies"
	accesspolicyResourceName    = "accesspolicy"
)

var (
	accesspoliciesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accesspoliciesMessagePrefix, `
		Delete Verify accesspolicy based on accesspolicyname.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete accesspolicy --entitlements`))

	accesspoliciesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an accesspolicy
		verifyctl delete accesspolicy --name=accesspolicyName`,
	))
)

type accesspoliciesOptions struct {
	options

	config *config.CLIConfig
}

func NewAccessPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &accesspoliciesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   accesspoliciesUsage,
		Short:                 cmdutil.TranslateShortDesc(accesspoliciesMessagePrefix, "Delete Verify accesspolicy based on an id."),
		Long:                  accesspoliciesLongDesc,
		Example:               accesspoliciesExamples,
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

func (o *accesspoliciesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.name, "accesspolicyName", o.name, i18n.Translate("accesspolicyName to be deleted"))
}

func (o *accesspoliciesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accesspoliciesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "accesspolicy" && o.name == "" {
		return module.MakeSimpleError(i18n.Translate("'accesspolicyName' flag is required."))
	}
	return nil
}

func (o *accesspoliciesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+accesspoliciesEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "accesspolicy" || len(o.name) > 0 {
		// deal with single accesspolicy
		return o.handleSingleAccessPolicy(cmd, auth, args)
	}
	return nil
}

func (o *accesspoliciesOptions) handleSingleAccessPolicy(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := security.NewAccesspolicyClient()
	err := c.DeleteAccesspolicy(cmd.Context(), auth, o.name)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.name)
	return nil
}
