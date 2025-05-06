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
	identitysourcesUsage         = `identitysources [flags]`
	identitysourcesMessagePrefix = "GetIdentitysources"
	identitysourcesEntitlements  = "Manage identitysources"
	identitysourceResourceName   = "identitysource"
)

var (
	identitysourcesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitysourcesMessagePrefix, `
		Get Verify identitysources based on an optional filter or a specific identitysource.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get identitysources --entitlements`))

	identitysourcesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an identitysource and print the output in yaml
		verifyctl get identitysource -o=yaml --instanceName="Cloud Directory"

		# Get 10 identitysources based on a given search criteria and sort it in the ascending order by name.
		verifyctl get identitysources --count=2 --sort=identitysourceName -o=yaml`))
)

type identitysourcesOptions struct {
	options

	config *config.CLIConfig
}

func NewIdentitysourceCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identitysourcesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identitysourcesUsage,
		Short:                 cmdutil.TranslateShortDesc(identitysourcesMessagePrefix, "Get Verify identitysources based on an optional filter or a specific identitysource."),
		Long:                  identitysourcesLongDesc,
		Example:               identitysourcesExamples,
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

func (o *identitysourcesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, identitysourceResourceName)
	cmd.Flags().StringVar(&o.name, "instanceName", o.name, i18n.Translate("Identitysource instanceName to get details"))
	o.addSortFlags(cmd, identitysourceResourceName)
	o.addCountFlags(cmd, identitysourceResourceName)
}

func (o *identitysourcesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitysourcesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "identitysource" && o.name == "" {
		return errorsx.G11NError("'displayName' flag is required.")
	}
	return nil
}

func (o *identitysourcesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identitysourcesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "identitysource" || len(o.name) > 0 {
		// deal with single identitysource
		return o.handleSingleIdentitysource(cmd, args)
	}

	return o.handleIdentitysourceList(cmd, args)
}

func (o *identitysourcesOptions) handleSingleIdentitysource(cmd *cobra.Command, _ []string) error {

	c := authentication.NewIdentitySourceClient()
	is, uri, err := c.GetIdentitysource(cmd.Context(), o.name)
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

func (o *identitysourcesOptions) handleIdentitysourceList(cmd *cobra.Command, _ []string) error {

	c := authentication.NewIdentitySourceClient()
	iss, uri, err := c.GetIdentitysources(cmd.Context(), o.sort, o.count)
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
