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
	accesspolicyUsage         = "accesspolicy [options]"
	accesspolicyMessagePrefix = "CreateAccesspolicy"
	accesspolicyEntitlements  = "Manage Access Policies"
	accesspolicyResourceName  = "accesspolicy"
)

var (
	accesspolicyShortDesc = cmdutil.TranslateShortDesc(accesspolicyMessagePrefix, "Additional options to create a accesspolicy.")

	accesspolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accesspolicyMessagePrefix, `
		Additional options to create a accesspolicy.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create accesspolicy --boilerplate

You can identify the entitlement required by running:

	verifyctl create accesspolicy --entitlements`))

	accesspolicyExamples = templates.Examples(cmdutil.TranslateExamples(accesspolicyMessagePrefix, `
		# Create an empty accesspolicy resource. This can be piped into a file.
		verifyctl create accesspolicy --boilerplate

		# Create a accesspolicy using a JSON file.
		verifyctl create accesspolicy -f=./accesspolicy.json`))
)

type accesspolicyOptions struct {
	options

	config *config.CLIConfig
}

func newAccesspolicyCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &accesspolicyOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   accesspolicyUsage,
		Short:                 accesspolicyShortDesc,
		Long:                  accesspolicyLongDesc,
		Example:               accesspolicyExamples,
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

func (o *accesspolicyOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, accesspolicyResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the JSON file containing accesspolicy data.")
}

func (o *accesspolicyOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accesspolicyOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("The 'file' option is required if no other options are used.")
	}
	return nil
}

func (o *accesspolicyOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+accesspolicyEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "AccessPolicy",
			APIVersion: "5.0",
			Data:       &security.Policy{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createAccesspolicy(cmd)
}

func (o *accesspolicyOptions) createAccesspolicy(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	// create accesspolicy with data
	return o.createAccesspolicyWithData(cmd, b)
}

func (o *accesspolicyOptions) createAccesspolicyWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accesspolicy
	accesspolicy := &security.Policy{}
	if err := json.Unmarshal(data, &accesspolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal the accesspolicy; err=%v", err)
		return err
	}

	client := security.NewAccesspolicyClient()
	resourceURI, err := client.CreateAccessPolicy(ctx, accesspolicy)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *accesspolicyOptions) createAccesspolicyFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accesspolicy
	accesspolicy := &security.Policy{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, accesspolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an accesspolicy; err=%v", err)
		return err
	}

	client := security.NewAccesspolicyClient()
	resourceURI, err := client.CreateAccessPolicy(ctx, accesspolicy)
	if err != nil {
		vc.Logger.Errorf("unable to create the accesspolicy; err=%v, accesspolicy=%+v", err, accesspolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
