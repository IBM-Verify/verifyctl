package replace

import (
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	passwordPolicyUsage         = `passwordpolicy [options]`
	passwordPolicyMessagePrefix = "UpdatePasswordPolicy"
	passwordPolicyEntitlements  = "Manage password policies"
	passwordPolicyResourceName  = "passwordpolicy"
)

var (
	passwordPolicyShortDesc = cmdutil.TranslateShortDesc(passwordPolicyMessagePrefix, "Update a password policy resource.")

	passwordPolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(passwordPolicyMessagePrefix, `
        Update a uspassword policy resource.
       
Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.
 
An empty resource file can be generated using:
 
    verifyctl replace passwordPolicy --boilerplate
 
You can identify the entitlement required by running:
 
  verifyctl replace passwordPolicy --entitlements`))

	passwordPolicyExamples = templates.Examples(cmdutil.TranslateExamples(passwordPolicyMessagePrefix, `
        # Generate an empty passwordPolicy resource template
        verifyctl replace passwordPolicy --boilerplate
       
        # Update a password policy from a JSON file
        verifyctl.go replace passwordPolicy -f "password_Policy_update.yaml"`))
)

type passwordPolicyOptions struct {
	options

	config *config.CLIConfig
}

func newPasswordPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &passwordPolicyOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   passwordPolicyUsage,
		Short:                 passwordPolicyShortDesc,
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
	o.addCommonFlags(cmd, passwordPolicyResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *passwordPolicyOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *passwordPolicyOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *passwordPolicyOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+passwordPolicyEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "PasswordPolicy",
			APIVersion: "3.0",
			Data: &security.PasswordPolicy{
				ID:         "<id>",
				PolicyName: "<name>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updatePasswordPolicy(cmd)
}

func (o *passwordPolicyOptions) updatePasswordPolicy(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)

	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}
	return o.updatePasswordPolicyWithData(cmd, b)
}

func (o *passwordPolicyOptions) updatePasswordPolicyWithData(cmd *cobra.Command, data []byte) error {

	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	passwordPolicy := &security.PasswordPolicy{}
	if err := yaml.Unmarshal(data, &passwordPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal the passwordPolicy; err=%v", err)
		return err
	}

	client := security.NewPasswordPolicyClient()
	if err := client.UpdatePasswordPolicy(ctx, passwordPolicy); err != nil {
		vc.Logger.Errorf("unable to update the password policy; err=%v, passwordPolicy=%+v", err, passwordPolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Password Policy updated successfully")
	return nil
}

func (o *passwordPolicyOptions) updatePasswordPolicyFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	passwordPolicy := &security.PasswordPolicy{}
	b, err := yaml.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := yaml.Unmarshal(b, passwordPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a password policy; err=%v", err)
		return err
	}

	client := security.NewPasswordPolicyClient()
	if err := client.UpdatePasswordPolicy(ctx, passwordPolicy); err != nil {
		vc.Logger.Errorf("unable to update password policy; err=%v, passwordPolicy=%+v", err, passwordPolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Password Policy updated successfully")
	return nil
}
