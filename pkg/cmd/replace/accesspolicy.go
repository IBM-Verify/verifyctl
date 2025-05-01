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
	accesspolicyUsage         = `accesspolicy [options]`
	accesspolicyMessagePrefix = "UpdateAccesspolicy"
	accesspolicyEntitlements  = "Manage accesspolicies"
	accesspolicyResourceName  = "accesspolicy"
)

var (
	accesspolicieshortDesc = cmdutil.TranslateShortDesc(accesspolicyMessagePrefix, "Update a accesspolicy resource.")

	accesspolicyLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accesspolicyMessagePrefix, `
		Update a accesspolicy resource.
		
Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl replace accesspolicy --boilerplate

You can identify the entitlement required by running:
  
  verifyctl replace accesspolicy --entitlements`))

	accesspolicyExamples = templates.Examples(cmdutil.TranslateExamples(accesspolicyMessagePrefix, `
		# Generate an empty accesspolicy resource template
		verifyctl replace accesspolicy --boilerplate
		
		# Update a accesspolicy from a JSON file
		verifyctl replace accesspolicy -f=./accesspolicy-12345.json`))
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
		Short:                 accesspolicieshortDesc,
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *accesspolicyOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accesspolicyOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required if no other options are used.")
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
			APIVersion: "2.0",
			Data: &security.Policy{
				Name: "<name>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.updateAccesspolicy(cmd, auth)
}

func (o *accesspolicyOptions) updateAccesspolicy(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateAccesspolicyWithData(cmd, b)
}

func (o *accesspolicyOptions) updateAccesspolicyWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accesspolicy object
	accesspolicy := &security.Policy{}
	if err := json.Unmarshal(data, &accesspolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal the accesspolicy; err=%v", err)
		return err
	}

	client := security.NewAccesspolicyClient()
	if err := client.UpdateAccesspolicy(ctx, accesspolicy); err != nil {
		vc.Logger.Errorf("unable to update the accesspolicy; err=%v, accesspolicy=%+v", err, accesspolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Access Policy updated successfully")
	return nil
}

func (o *accesspolicyOptions) updateAccesspolicyFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to accesspolicy object
	accesspolicy := &security.Policy{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, accesspolicy); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a accesspolicy; err=%v", err)
		return err
	}

	client := security.NewAccesspolicyClient()
	if err := client.UpdateAccesspolicy(ctx, accesspolicy); err != nil {
		vc.Logger.Errorf("unable to update the accesspolicy; err=%v, accesspolicy=%+v", err, accesspolicy)
		return err
	}

	cmdutil.WriteString(cmd, "Access Policy updated successfully")
	return nil
}
