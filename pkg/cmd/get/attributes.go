package get

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/directory"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	attributesUsage         = `attributes [flags]`
	attributesMessagePrefix = "GetAttributes"
	attributesEntitlements  = "Manage attributes"
	attributeResourceName   = "attribute"
)

var (
	attributesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(attributesMessagePrefix, `
		Get Verify attributes based on an optional filter or a specific attribute.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get attributes --entitlements`))

	attributesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an attribute and print the output in yaml
		verifyctl get attribute -o=yaml --id=work_email

		# Get 10 attributes based on a given search criteria and sort it in the ascending order by name.
		verifyctl get attributes --search="tags=\"sso\"" --limit=10 --page=1 --sort=+name -o=yaml`))
)

type attributesOptions struct {
	options

	config *config.CLIConfig
}

func NewAttributesCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &attributesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   attributesUsage,
		Short:                 cmdutil.TranslateShortDesc(attributesMessagePrefix, "Get Verify attributes based on an optional filter or a specific attribute."),
		Long:                  attributesLongDesc,
		Example:               attributesExamples,
		Aliases:               []string{"attribute"},
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

func (o *attributesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, attributeResourceName)
	o.addIdFlag(cmd, attributeResourceName)
	o.addPaginationFlags(cmd, attributeResourceName)
	o.addSearchFlags(cmd, attributeResourceName)
	o.addSortFlags(cmd, attributeResourceName)
}

func (o *attributesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *attributesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "attribute" && o.id == "" {
		return module.MakeSimpleError(i18n.Translate("'id' flag is required."))
	}
	return nil
}

func (o *attributesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+attributesEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "attribute" || len(o.id) > 0 {
		// deal with single attribute
		return o.handleSingleAttribute(cmd, auth, args)
	}

	return o.handleAttributeList(cmd, auth, args)
}

func (o *attributesOptions) handleSingleAttribute(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewAttributeClient()
	attr, uri, err := c.GetAttribute(cmd.Context(), auth, o.id)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, attr, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "Attribute",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  *attr.ID,
			Name: attr.Name,
			URI:  uri,
		},
		Data: attr,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *attributesOptions) handleAttributeList(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewAttributeClient()
	attrs, uri, err := c.GetAttributes(cmd.Context(), auth, o.search, o.sort, o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, attrs, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, attr := range attrs.Attributes {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Attribute",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  *attr.ID,
				Name: attr.Name,
			},
			Data: attr,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Limit: attrs.Limit,
			Count: attrs.Count,
			Total: attrs.Total,
			Page:  attrs.Page,
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
