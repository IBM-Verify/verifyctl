package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	attributeUsage         = "attribute [options]"
	attributeMessagePrefix = "DeleteAttribute"
	attributeEntitlements  = "Manage attributes"
	attributeResourceName  = "attribute"
)

var (
	attributeLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(attributeMessagePrefix, `
        Delete an attribute in IBM Security Verify based on attribute ID.
        Resources managed on Verify have specific entitlements, so ensure that the
        application or API client used with the 'auth' command is configured with
        the appropriate entitlements.
 
        You can identify the entitlement required by running:
            verifyctl delete attribute --entitlements`))

	attributeExamples = templates.Examples(cmdutil.TranslateExamples(attributeMessagePrefix, `
        # Delete an attribute by ID
        verifyctl delete attribute --id=some-attribute-id
    `))
)

type attributeOptions struct {
	options
	id     string
	config *config.CLIConfig
}

func NewAttributeCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &attributeOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   attributeUsage,
		Short:                 cmdutil.TranslateShortDesc(attributeMessagePrefix, "Delete Verify attribute based on attribute ID."),
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
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.id, "id", o.id, i18n.Translate("Identifier of the attribute to delete. (Required)"))
}

func (o *attributeOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *attributeOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}
	calledAs := cmd.CalledAs()
	if calledAs == "attribute" && o.id == "" {
		return errorsx.G11NError(i18n.Translate("The 'id' flag is required to delete an attribute"))
	}
	return nil
}

func (o *attributeOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+" "+attributeEntitlements)
		return nil
	}
	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}
	if cmd.CalledAs() == "attribute" || len(o.id) > 0 {
		return o.handleSingleAttribute(cmd, args)
	}
	return nil
}

func (o *attributeOptions) handleSingleAttribute(cmd *cobra.Command, _ []string) error {
	c := directory.NewAttributeClient()
	err := c.DeleteAttributeByID(cmd.Context(), o.id)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.id)
	return nil
}
