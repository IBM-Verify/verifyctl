package get

import (
	"io"

	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/module"
	"github.com/ibm-verify/verifyctl/pkg/module/security"
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
		verifyctl get apiclient -o=yaml --name=testApiclient

		# Get 10 apiclients based on a given search criteria and sort it in the ascending order by name.
		verifyctl get apiclients --count=2 --sort=apiclientName -o=yaml`))
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
	o.addSortFlags(cmd, apiclientResourceName)
	o.addCountFlags(cmd, apiclientResourceName)
}

func (o *apiclientsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *apiclientsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "apiclient" && o.name == "" {
		return module.MakeSimpleError(i18n.Translate("'clientName' flag is required."))
	}
	return nil
}

func (o *apiclientsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+apiclientsEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "apiclient" || len(o.name) > 0 {
		return o.handleSingleAPIClient(cmd, auth, args)
	}

	return o.handleAPIClientList(cmd, auth, args)
}

func (o *apiclientsOptions) handleSingleAPIClient(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := security.NewAPIClient()
	apic, uri, err := c.GetAPIClient(cmd.Context(), auth, o.name)
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

func (o *apiclientsOptions) handleAPIClientList(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := security.NewAPIClient()
	apiclis, uri, err := c.GetAPIClients(cmd.Context(), auth, o.search, o.sort, o.page, o.limit)
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
			Total: int(*apiclis.Total),
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
