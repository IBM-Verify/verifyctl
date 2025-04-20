package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	attributeUsage         = `attribute [options]`
	attributeMessagePrefix = "CreateAttribute"
	attributeEntitlements  = "Manage attributes"
	attributeResourceName  = "attribute"
)

var (
	attributeShortDesc = cmdutil.TranslateShortDesc(attributeMessagePrefix, "Additional options to create an attribute.")

	attributeLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(attributeMessagePrefix, `
		Additional options to create an attribute.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create attribute --boilerplate

You can identify the entitlement required by running:
  
  verifyctl create attribute --entitlements`))

	attributeExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Create an empty attribute resource. This can be piped into a file.
		verifyctl create attribute --boilerplate
		
		# Create an attribute using the API model in JSON format.
		verifyctl create attribute -f=./customEmail.json`))
)

type attributeOptions struct {
	options

	config *config.CLIConfig
}

func newAttributeCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &attributeOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   attributeUsage,
		Short:                 attributeShortDesc,
		Long:                  attributeLongDesc,
		Example:               attributeExamples,
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

func (o *attributeOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, attributeResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *attributeOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *attributeOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required if no other options are used.")
	}
	return nil
}

func (o *attributeOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+attributeEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Attribute",
			APIVersion: "1.0",
			Data: &directory.Attribute{
				Tags: &[]string{"sso"},
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.createAttribute(cmd)
}

func (o *attributeOptions) createAttribute(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	// create attribute with data
	return o.createAttributeWithData(cmd, b)
}

func (o *attributeOptions) createAttributeWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to attribute
	attribute := &directory.Attribute{}
	if err := json.Unmarshal(data, &attribute); err != nil {
		vc.Logger.Errorf("unable to unmarshal the attribute; err=%v", err)
		return err
	}

	client := directory.NewAttributeClient()
	resourceURI, err := client.CreateAttribute(ctx, attribute)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *attributeOptions) createAttributeFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to attribute
	attribute := &directory.Attribute{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, attribute); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an attribute; err=%v", err)
		return err
	}

	client := directory.NewAttributeClient()
	resourceURI, err := client.CreateAttribute(ctx, attribute)
	if err != nil {
		vc.Logger.Errorf("unable to create the attribute; err=%v, attribute=%+v", err, attribute)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
