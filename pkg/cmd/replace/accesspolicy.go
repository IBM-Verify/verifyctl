package replace

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
)

const (
	accessPolicyUsage         = `accesspolicy [options]`
	accessPolicyMessagePrefix = "UpdateAccessPolicy"
	accessPolicyEntitlements  = "Manage accessPolicies"
	accessPolicyResourceName  = "accesspolicy"
)

var (
	accessPolicieshortDesc = cmdutil.TranslateShortDesc(accessPolicyMessagePrefix, "Update a accessPolicy resource.")

	accessPolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accessPolicyMessagePrefix, `
		Update a accessPolicy resource.
		
Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl replace accesspolicy --boilerplate

You can identify the entitlement required by running:
  
  verifyctl replace accesspolicy --entitlements`))

	accessPolicyExamples = templates.Examples(cmdutil.TranslateExamples(accessPolicyMessagePrefix, `
		# Generate an empty accessPolicy resource template
		verifyctl replace accesspolicy --boilerplate
		
		# Update a accessPolicy from a YAML file
		verifyctl replace -f "accesspolicy.yaml"`))
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
		Short:                 accessPolicieshortDesc,
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *accessPolicyOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accessPolicyOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required if no other options are used.")
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
			APIVersion: "2.0",
			Data: &security.Policy{
				Name: "<name>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateAccessPolicy(cmd)
}

func (o *accessPolicyOptions) updateAccessPolicy(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateAccessPolicyWithData(cmd, b)
}

func (o *accessPolicyOptions) updateAccessPolicyWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accessPolicy object
	accessPolicy := &security.Policy{}
	if err := json.Unmarshal(data, &accessPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal the accessPolicy; err=%v", err)
		return err
	}

	client := security.NewAccessPolicyClient()
	if err := client.UpdateAccessPolicy(ctx, accessPolicy); err != nil {
		vc.Logger.Errorf("unable to update the accessPolicy; err=%v, accessPolicy=%+v", err, accessPolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Access Policy updated successfully")
	return nil
}

func (o *accessPolicyOptions) updateAccessPolicyFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accessPolicy object
	accessPolicy := &security.Policy{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, accessPolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a accessPolicy; err=%v", err)
		return err
	}

	client := security.NewAccessPolicyClient()
	if err := client.UpdateAccessPolicy(ctx, accessPolicy); err != nil {
		vc.Logger.Errorf("unable to update the accessPolicy; err=%v, accessPolicy=%+v", err, accessPolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Access Policy updated successfully")
	return nil
}
