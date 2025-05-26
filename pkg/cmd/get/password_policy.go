package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	passwordPolicyUsage         = `passwordpolicies [flags]`
	passwordPolicyMessagePrefix = "GetPasswordPolicies"
	passwordPolicyEntitlements  = "Manage password policies"
	passwordPolicyResourceName  = "passwordpolicy"
)

var (
	passwordPolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(passwordPolicyMessagePrefix, `
Get Verify password policies based on an optional filter or a specific password policy.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:

verifyctl get passwordpolicy --entitlements`))

	passwordPolicyExamples = templates.Examples(cmdutil.TranslateExamples(passwordPolicyMessagePrefix, `
# Get a specific password policy by ID
verifyctl get passwordpolicy -o=yaml --passwordPolicyID=testPasswordPolicyID

# Get 2 policies based on a given search criteria and sort it in the ascending order by name.
		verifyctl get passwordpolicies --count=2 --sort=policyName -o=yaml
`))
)

type passwordPolicyOptions struct {
	options
	passwordPolicyID string
	config           *config.CLIConfig
}

func newPasswordPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &passwordPolicyOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   passwordPolicyUsage,
		Short:                 cmdutil.TranslateShortDesc(passwordPolicyMessagePrefix, "Get Verify password policies based on an optional filter or a specific policy."),
		Long:                  passwordPolicyLongDesc,
		Example:               passwordPolicyExamples,
		Aliases:               []string{"passwordpolicy"},
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
	o.addCommonFlags(cmd, passwordPolicyResourceName)
	cmd.Flags().StringVar(&o.passwordPolicyID, "passwordPolicyID", o.passwordPolicyID, i18n.Translate("passwordPolicyID to get details"))
	o.addSortFlags(cmd, passwordPolicyResourceName)
	o.addCountFlags(cmd, passwordPolicyResourceName)
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
		return errorsx.G11NError(i18n.Translate("'passwordPolicyID' flag is required."))
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

	return o.handlePasswordPolicyList(cmd, args)
}

func (o *passwordPolicyOptions) handleSinglePasswordPolicy(cmd *cobra.Command, _ []string) error {

	c := security.NewPasswordPolicyClient()
	pwd, uri, err := c.GetPasswordPolicyByID(cmd.Context(), o.passwordPolicyID)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, pwd, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "PasswordPolicy",
		APIVersion: "3.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  pwd.ID,
			Name: pwd.PolicyName,
			URI:  uri,
		},
		Data: pwd,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *passwordPolicyOptions) handlePasswordPolicyList(cmd *cobra.Command, _ []string) error {

	c := security.NewPasswordPolicyClient()
	pwds, uri, err := c.GetPasswordPolicies(cmd.Context(), o.sort, o.count)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, pwds, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, pwd := range pwds.PasswordPolicies {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "PasswordPolicy",
			APIVersion: "3.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  pwd.ID,
				Name: pwd.PolicyName,
			},
			Data: pwd,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "3.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: pwds.TotalResults,
		},
		Items: items,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}
