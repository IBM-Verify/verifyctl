package get

import (
	"io"

	"github.com/spf13/cobra"
	"github.ibm.com/sec-ci/devops-experiments/pkg/cmd/resource"
	"github.ibm.com/sec-ci/devops-experiments/pkg/config"
	"github.ibm.com/sec-ci/devops-experiments/pkg/i18n"
	"github.ibm.com/sec-ci/devops-experiments/pkg/module"
	"github.ibm.com/sec-ci/devops-experiments/pkg/module/directory"
	cmdutil "github.ibm.com/sec-ci/devops-experiments/pkg/util/cmd"
	"github.ibm.com/sec-ci/devops-experiments/pkg/util/templates"
)

const (
	apiclientUsage          = `apiclients [flags]`
	apiclientsMessagePrefix = "Getapiclients"
	apiclientsEntitlements  = "Manage apiclients"
	apiclientResourceName   = "apiclient"
)

var (
	apiclientLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(apiclientsMessagePrefix, `
		Get Verify apiclients based on an optional filter or a specific apiclient.
		
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

func NewAPIclientsCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &apiclientsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   apiclientUsage,
		Short:                 cmdutil.TranslateShortDesc(apiclientsMessagePrefix, "Get Verify api clients based on an optional filter or a specific api client."),
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
		return o.handleSingleApiClient(cmd, auth, args)
	}

	return o.handleApiClientList(cmd, auth, args)
}

func (o *apiclientsOptions) handleSingleApiClient(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewApiClient()
	apic, uri, err := c.GetApiClient(cmd.Context(), auth, o.name)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, apic, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "Apiclient",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  apic.ClientID,
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

func (o *apiclientsOptions) handleApiClientList(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewApiClient()
	apiclis, uri, err := c.GetApiClients(cmd.Context(), auth, o.search, o.sort, o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, apiclis, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, apic := range apiclis.Clients {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Apiclient",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  apic.ClientID,
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
			Total: apiclis.Total,
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
