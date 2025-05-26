package replace

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
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
	signInOptionsUsage         = `sign-in-options [options]`
	signInOptionsMessagePrefix = "UpdateSignInOptions"
	signInOptionsEntitlements  = "Manage identitySources"
	signInOptionsResourceName  = "identitySourceSignIn"
)

var (
	signInOptionsShortDesc = cmdutil.TranslateShortDesc(signInOptionsMessagePrefix, "Update sign-in options for an identity provider.")
	signInOptionsLongDesc  = templates.LongDesc(cmdutil.TranslateLongDesc(signInOptionsMessagePrefix, `
		Update sign-in options for an identity provider. This includes enabling/disabling sign-in options for admins and end users, including QR code and FIDO2 authentication.
		An empty resource file can be generated using:
			verifyctl replace sign-in-options --boilerplate
		You can identify the entitlement required by running:
			verifyctl replace sign-in-options --entitlements`))

	signInOptionsExamples = templates.Examples(cmdutil.TranslateExamples(signInOptionsMessagePrefix, `
		# Generate an empty sign-in options template
		verifyctl replace --boilerplate
 
		# Update sign-in options for an identity provider from a YAML file
		verifyctl replace -f=./signin-options.yaml`))
)

type signInOptions struct {
	options

	config *config.CLIConfig
}

func newSignInOptionsCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &signInOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   signInOptionsUsage,
		Short:                 signInOptionsShortDesc,
		Long:                  signInOptionsLongDesc,
		Example:               signInOptionsExamples,
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

func (o *signInOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, signInOptionsResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the sign-in options data (JSON/YAML format)."))
}

func (o *signInOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *signInOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}
	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required if no other options are used.")
	}
	return nil
}

func (o *signInOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+" "+signInOptionsEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "SignInOptions",
			APIVersion: "2.0",
			Data:       authentication.GetSignInOptions(),
		}
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateSignInOptions(cmd)
}

func (o *signInOptions) updateSignInOptions(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	resourceObj := &resource.ResourceObject{}
	if err := yaml.Unmarshal(b, resourceObj); err != nil {
		vc.Logger.Errorf("unable to unmarshal file into resource object; err=%v", err)
		return err
	}

	data, err := json.Marshal(resourceObj.Data)
	if err != nil {
		vc.Logger.Errorf("unable to marshal Data field; err=%v", err)
		return err
	}

	return o.updateSignInOptionsWithData(cmd, data)
}

func (o *signInOptions) updateSignInOptionsWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	signInOptions := &authentication.IdentitySource{}
	if err := json.Unmarshal(data, signInOptions); err != nil {
		vc.Logger.Errorf("unable to unmarshal the Sign-in Options; err=%v", err)
		return err
	}

	client := authentication.NewIdentitySourceClient()
	if err := client.UpdateSignInOptions(ctx, signInOptions); err != nil {
		vc.Logger.Errorf("unable to update the Sign-in Options; err=%v, signInOptions=%+v", err, signInOptions)
		return err
	}

	cmdutil.WriteString(cmd, "Sign-in options updated successfully")
	return nil
}

func (o *signInOptions) updateSignInOptionsFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	signInOptions := &authentication.IdentitySource{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, signInOptions); err != nil {
		vc.Logger.Errorf("unable to unmarshal to Sign-in Options; err=%v", err)
		return err
	}

	client := authentication.NewIdentitySourceClient()
	if err := client.UpdateSignInOptions(ctx, signInOptions); err != nil {
		vc.Logger.Errorf("unable to update the Sign-in Options; err=%v, signInOptions=%+v", err, signInOptions)
		return err
	}

	cmdutil.WriteString(cmd, "Sign-in options updated successfully")
	return nil
}
