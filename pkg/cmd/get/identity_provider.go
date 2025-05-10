package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	identitySourcesUsage         = `identitysources [flags]`
	identitySourcesMessagePrefix = "GetIdentitySources"
	identitySourcesEntitlements  = "Manage identitySources"
	identitySourceResourceName   = "identitysource"
)

var (
	identitySourcesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitySourcesMessagePrefix, `
		Get Verify identitySources based on an optional filter or a specific identitySource.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get identitysources --entitlements`))

	identitySourcesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an identitySource and print the output in yaml
		verifyctl get identitysource -o=yaml --instanceName="Cloud Directory"

		# Get 10 identitySources based on a given search criteria and sort it in the ascending order by name.
		verifyctl get identitysources --count=2 --sort=identitysourceName -o=yaml`))
)

type identitySourcesOptions struct {
	options

	config *config.CLIConfig
}

func NewIdentitySourceCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identitySourcesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identitySourcesUsage,
		Short:                 cmdutil.TranslateShortDesc(identitySourcesMessagePrefix, "Get Verify identitySources based on an optional filter or a specific identitySource."),
		Long:                  identitySourcesLongDesc,
		Example:               identitySourcesExamples,
		Aliases:               []string{"identitysource"},
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

func (o *identitySourcesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, identitySourceResourceName)
	cmd.Flags().StringVar(&o.name, "instanceName", o.name, i18n.Translate("IdentitySource instanceName to get details"))
	o.addSortFlags(cmd, identitySourceResourceName)
	o.addCountFlags(cmd, identitySourceResourceName)
}

func (o *identitySourcesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitySourcesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "identitysource" && o.name == "" {
		return errorsx.G11NError("'displayName' flag is required.")
	}
	return nil
}

func (o *identitySourcesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identitySourcesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "identitysource" || len(o.name) > 0 {
		// deal with single identitySource
		return o.handleSingleIdentitySource(cmd, args)
	}

	return o.handleIdentitySourceList(cmd, args)
}

func (o *identitySourcesOptions) handleSingleIdentitySource(cmd *cobra.Command, _ []string) error {

	c := authentication.NewIdentitySourceClient()
	is, uri, err := c.GetIdentitySource(cmd.Context(), o.name)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, is, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "IdentitySource",
		APIVersion: "2.0",
		Metadata: &resource.ResourceObjectMetadata{
			Name: is.InstanceName,
			URI:  uri,
		},
		Data: is,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *identitySourcesOptions) handleIdentitySourceList(cmd *cobra.Command, _ []string) error {

	c := authentication.NewIdentitySourceClient()
	iss, uri, err := c.GetIdentitySources(cmd.Context(), o.sort, o.count)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, iss, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, is := range iss.IdentitySources {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "IdentitySource",
			APIVersion: "2.0",
			Metadata: &resource.ResourceObjectMetadata{
				Name: is.InstanceName,
			},
			Data: is,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "2.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: int(iss.Total),
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
