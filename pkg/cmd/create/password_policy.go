package create

import (
	"encoding/json"
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
	passwordPolicyMessagePrefix = "CreatePasswordPolicy"
	passwordPolicyEntitlements  = "Manage password policies"
	passwordPolicyResourceName  = "passwordpolicy"
)

var (
	passwordPolicyShortDesc = cmdutil.TranslateShortDesc(
		passwordPolicyMessagePrefix,
		"Additional options to create a password policy.",
	)
	passwordPolicyLongDesc = templates.LongDesc(
		cmdutil.TranslateLongDesc(
			passwordPolicyMessagePrefix,
			`Additional options to create a password policy.
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:
  verifyctl create passwordpolicy --boilerplate

You can identify the entitlement required by running:
  verifyctl create passwordpolicy --entitlements`,
		),
	)
	passwordPolicyExamples = templates.Examples(
		cmdutil.TranslateExamples(
			passwordPolicyMessagePrefix,
			`# Create an empty password policy resource.
verifyctl create passwordpolicy --boilerplate

# Create a password policy using the API model in YAML format.
verifyctl create passwordpolicy -f=./password_Policy.yaml`,
		),
	)
)

type passwordPolicyOptions struct {
	options
	file string
}

func newPasswordPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &passwordPolicyOptions{
		options: options{
			config: config,
		},
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the YAML file that contains the input data."))
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
			Data:       &security.PasswordPolicy{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createPasswordPolicy(cmd)
}

func (o *passwordPolicyOptions) createPasswordPolicy(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createPasswordPolicyWithData(cmd, b)
}

func (o *passwordPolicyOptions) createPasswordPolicyWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	passwordPolicy := &security.PasswordPolicy{}
	if err := yaml.Unmarshal(data, &passwordPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal the passwordPolicy; err=%v", err)
		return err
	}

	client := security.NewPasswordPolicyClient()
	resourceURI, err := client.CreatePasswordPolicy(ctx, passwordPolicy)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *passwordPolicyOptions) createPasswordPolicyFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	passwordPolicy := &security.PasswordPolicy{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map into json; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, passwordPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an passwordPolicy; err=%v", err)
		return err
	}

	client := security.NewPasswordPolicyClient()
	resourceURI, err := client.CreatePasswordPolicy(ctx, passwordPolicy)
	if err != nil {
		vc.Logger.Errorf("unable to create the password policy; err=%v, passwordPolicy=%+v", err, passwordPolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
