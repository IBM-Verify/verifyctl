package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	accessPolicyUsage         = "accesspolicy [options]"
	accessPolicyMessagePrefix = "CreateAccessPolicy"
	accessPolicyEntitlements  = "Manage Access Policies"
	accessPolicyResourceName  = "accesspolicy"
)

var (
	accessPolicyShortDesc = cmdutil.TranslateShortDesc(accessPolicyMessagePrefix, "Additional options to create a accessPolicy.")

	accessPolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accessPolicyMessagePrefix, `
		Additional options to create a accessPolicy.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create accesspolicy --boilerplate

You can identify the entitlement required by running:

	verifyctl create accesspolicy --entitlements`))

	accessPolicyExamples = templates.Examples(cmdutil.TranslateExamples(accessPolicyMessagePrefix, `
		# Create an empty accessPolicy resource. This can be piped into a file.
		verifyctl create accesspolicy --boilerplate

		# Create a accessPolicy using a JSON file.
		verifyctl create accesspolicy -f=./accesspolicy.json`))
)

type accessPolicyOptions struct {
	options

	config *config.CLIConfig
}

func newAccessPolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &accessPolicyOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   accessPolicyUsage,
		Short:                 accessPolicyShortDesc,
		Long:                  accessPolicyLongDesc,
		Example:               accessPolicyExamples,
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

func (o *accessPolicyOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, accessPolicyResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the JSON file containing accessPolicy data.")
}

func (o *accessPolicyOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accessPolicyOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("The 'file' option is required if no other options are used.")
	}
	return nil
}

func (o *accessPolicyOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+accessPolicyEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "AccessPolicy",
			APIVersion: "5.0",
			Data:       (&security.Policy{}).Example(),
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createAccessPolicy(cmd)
}

func (o *accessPolicyOptions) createAccessPolicy(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	// create accessPolicy with data
	return o.createAccessPolicyWithData(cmd, b)
}

func (o *accessPolicyOptions) createAccessPolicyWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accessPolicy
	accessPolicy := &security.Policy{}
	if err := json.Unmarshal(data, &accessPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal the accessPolicy; err=%v", err)
		return err
	}

	client := security.NewAccessPolicyClient()
	resourceURI, err := client.CreateAccessPolicy(ctx, accessPolicy)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *accessPolicyOptions) createAccessPolicyFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accessPolicy
	accessPolicy := &security.Policy{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, accessPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an accessPolicy; err=%v", err)
		return err
	}

	client := security.NewAccessPolicyClient()
	resourceURI, err := client.CreateAccessPolicy(ctx, accessPolicy)
	if err != nil {
		vc.Logger.Errorf("unable to create the accessPolicy; err=%v, accessPolicy=%+v", err, accessPolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
