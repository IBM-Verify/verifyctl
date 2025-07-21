package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	apiclientUsage          = `apiclients [flags]`
	apiclientsMessagePrefix = "Getapiclients"
	apiclientsEntitlements  = "Manage apiclients"
	apiclientResourceName   = "apiclient"
)

var (
	apiclientLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(apiclientsMessagePrefix, `
		Get API clients based on an optional filter or a specific apiclient.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get apiclients --entitlements`))

	apiclientsExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an apiclient and print the output in yaml
		verifyctl get apiclient -o=yaml --clientName=testApiclient
		verifyctl get apiclient -o=yaml --clientID=12345

		# Get 2 apiclients 
		verifyctl get apiclients --limit=2 --page=1 -o=yaml`))
)

type apiclientsOptions struct {
	options

	config *config.CLIConfig
}

func NewAPIClientsCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &apiclientsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   apiclientUsage,
		Short:                 cmdutil.TranslateShortDesc(apiclientsMessagePrefix, "Get API clients based on an optional filter or a specific api client."),
		Long:                  apiclientLongDesc,
		Example:               apiclientsExamples,
		Aliases:               []string{"apiclient"},
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

func (o *apiclientsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, apiclientResourceName)
	cmd.Flags().StringVar(&o.name, "clientName", o.name, i18n.Translate("clientName to get details"))
	cmd.Flags().StringVar(&o.id, "clientID", o.id, i18n.Translate("clientID to get details"))
	o.addSortFlags(cmd, apiclientResourceName)
	o.addPaginationFlags(cmd, apiclientResourceName)
}

func (o *apiclientsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *apiclientsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "apiclient" && o.name == "" && o.id == "" {
		return errorsx.G11NError("either 'clientName' or 'clientID' flag is required.")
	}
	if o.name != "" && o.id != "" {
		return errorsx.G11NError("only one of 'clientName' or 'clientID' can be provided")
	}
	return nil
}

func (o *apiclientsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+apiclientsEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "apiclient" || len(o.name) > 0 || len(o.id) > 0 {
		return o.handleSingleAPIClient(cmd, args)
	}

	return o.handleAPIClientList(cmd, args)
}

func (o *apiclientsOptions) handleSingleAPIClient(cmd *cobra.Command, _ []string) error {

	c := security.NewAPIClient()
	var apic *security.APIClientConfig
	var uri string
	var err error

	if o.id != "" {
		apic, uri, err = c.GetAPIClientByID(cmd.Context(), o.id)
	} else {
		apic, uri, err = c.GetAPIClientByName(cmd.Context(), o.name)
	}
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, apic, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "APIClient",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  *apic.ClientID,
			Name: apic.ClientName,
			URI:  uri,
		},
		Data: apic,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *apiclientsOptions) handleAPIClientList(cmd *cobra.Command, _ []string) error {

	c := security.NewAPIClient()
	apiclis, uri, err := c.GetAPIClients(cmd.Context(), o.search, o.sort, o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, apiclis, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, apic := range *apiclis.APIClients {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "APIClient",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  *apic.ClientID,
				Name: apic.ClientName,
			},
			Data: apic,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: len(items),
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
