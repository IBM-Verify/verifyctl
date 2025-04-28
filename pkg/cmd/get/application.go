package get

import (
	"io"
	"strings"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/applications"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	applicationUsage          = "applications [options]"
	applicationsMessagePrefix = "GetApplications"
	applicationsEntitlements  = "Manage applications"
	applicationResourceName   = "application"
)

var (
	applicationLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(applicationsMessagePrefix, `
        Get Verify application based on an optional filter or a specific application.
        Resources managed on Verify have specific entitlements, so ensure that the application or application used with the 'auth' command is configured with the appropriate entitlements.
        You can identify the entitlement required by running: verifyctl get application --entitlements`))

	applicationExamples = templates.Examples(cmdutil.TranslateExamples(applicationsMessagePrefix, `
        # Get an application and print the output in yaml
        verifyctl get application -o=yaml --name=testApplication
 
        # Get 10 applications based on a given search criteria and sort it in the ascending order by name.
        verifyctl get applications --count=2 --sort=applicationName -o=yaml`))
)

type applicationsOptions struct {
	options

	config *config.CLIConfig
}

func NewApplicationsCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &applicationsOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   applicationUsage,
		Short:                 cmdutil.TranslateShortDesc(applicationsMessagePrefix, "Get Verify applications based on an optional filter or a specific application."),
		Long:                  applicationLongDesc,
		Example:               applicationExamples,
		Aliases:               []string{"application"},
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

func (o *applicationsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, applicationResourceName)
	cmd.Flags().StringVar(&o.name, "name", o.name, i18n.Translate("name to get details"))
	o.addSortFlags(cmd, applicationResourceName)
	o.addCountFlags(cmd, applicationResourceName)
}

func (o *applicationsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *applicationsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}
	calledAs := cmd.CalledAs()
	if calledAs == "application" && o.name == "" {
		return errorsx.G11NError(i18n.Translate("'name' flag is required."))
	}
	return nil
}

func (o *applicationsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+" "+applicationsEntitlements)
		return nil
	}
	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}
	if cmd.CalledAs() == "application" || len(o.name) > 0 {
		return o.handleSingleApplicationClient(cmd, args)
	}
	return o.handleApplicationClientList(cmd, args)
}

func (o *applicationsOptions) handleSingleApplicationClient(cmd *cobra.Command, _ []string) error {
	c := applications.NewApplicationClient()

	appl, uri, err := c.GetApplication(cmd.Context(), o.name)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, appl, cmd.OutOrStdout())
		return nil
	}

	id := appl.Links.Self.Href
	if idx := strings.LastIndex(id, "/"); idx != -1 {
		id = id[idx+1:]
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "Application",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  appl.TemplateID,
			Name: appl.Name,
			URI:  uri,
		},
		Data: appl,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *applicationsOptions) handleApplicationClientList(cmd *cobra.Command, _ []string) error {
	c := applications.NewApplicationClient()
	appls, uri, err := c.GetApplications(cmd.Context(), o.search, o.sort, o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, appls, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, appl := range *appls.Embedded.Applications {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Application",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  appl.TemplateID,
				Name: appl.Name,
			},
			Data: appl,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: int(*appls.TotalCount),
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
