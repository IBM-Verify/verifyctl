package get

import (
	"io"

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
        verifyctl get application -o=yaml --applicationID "testApplicationID"
 
        # Get 2 applications
        verifyctl get applications --limit=2 --page=1 -o=yaml

		# To sort applications [To sort results, supported values are 'name' and 'applicationID'. Prepend the attribute with '+' or '-' sign for ascending and descending sorted order respectively. If not specified, sorted in ascending order on applicationID.]
		verifyctl get applications --sort "-name"`))
)

type applicationsOptions struct {
	options
	applicationID string
	config        *config.CLIConfig
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
	cmd.Flags().StringVar(&o.applicationID, "applicationID", o.applicationID, i18n.Translate("applicationID to get details"))
	o.addSortFlags(cmd, applicationResourceName)
	o.addPaginationFlags(cmd, applicationResourceName)
}

func (o *applicationsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *applicationsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}
	calledAs := cmd.CalledAs()
	if calledAs == "application" && o.applicationID == "" {
		return errorsx.G11NError(i18n.Translate("'applicationID' flag is required."))
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
	if cmd.CalledAs() == "application" || len(o.applicationID) > 0 {
		return o.handleSingleApplicationClient(cmd, args)
	}
	return o.handleApplicationClientList(cmd, args)
}

func (o *applicationsOptions) handleSingleApplicationClient(cmd *cobra.Command, _ []string) error {
	c := applications.NewApplicationClient()

	appl, uri, err := c.GetApplicationByID(cmd.Context(), o.applicationID)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, appl, cmd.OutOrStdout())
		return nil
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
	if o.sort == "+applicationID" {
		o.sort = "+entityid"
	} else if o.sort == "-applicationID" {
		o.sort = "-entityid"
	}
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
