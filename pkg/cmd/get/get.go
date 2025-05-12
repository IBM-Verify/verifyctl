package get

import (
	"io"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usage         = "get [resource-type] [flags]"
	messagePrefix = "Get"
)

var (
	longDesc = templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `
		Get a Verify managed resource, such as an application, user, API client etc.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get [resource-type] --entitlements
  
The flags supported by each resource type may differ and can be determined using:

  verifyctl get [resource-type] -h`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an application
		verifyctl get application -o=yaml --id=1098012

		# Get all users that match department "2A". There may be limits introduced by the API.
		verifyctl get users --filter="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq \"2A\"" --attributes="userName,emails,urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager" -o yaml`))

	entitlementsMessage = i18n.Translate("Choose any of the following entitlements to configure your application or API client:\n")
)

type options struct {
	resource     string
	entitlements bool
	output       string
	limit        int
	page         int
	sort         string
	search       string
	count        string
	//properties   string
	id   string
	name string

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter, groupID string) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 cmdutil.TranslateShortDesc(messagePrefix, "Get a Verify managed resource."),
		Long:                  longDesc,
		Example:               examples,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
		},
		GroupID: groupID,
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	// add sub commands
	cmd.AddCommand(NewAttributesCommand(config, streams))
	cmd.AddCommand(NewThemesCommand(config, streams))
	cmd.AddCommand(NewUsersCommand(config, streams))
	cmd.AddCommand(NewGroupsCommand(config, streams))
	cmd.AddCommand(NewAccesspoliciesCommand(config, streams))
	cmd.AddCommand(NewIdentitysourceCommand(config, streams))
	cmd.AddCommand(NewAPIClientsCommand(config, streams))
	cmd.AddCommand(NewApplicationsCommand(config, streams))

	return cmd
}

func (o *options) addCommonFlags(cmd *cobra.Command, resourceName string) {
	cmd.Flags().BoolVar(&o.entitlements, "entitlements", o.entitlements, i18n.TranslateWithArgs("List the entitlements that can be configured to grant access to the %s. This is useful to know what to configure on the application or API client used to generate the login token. When this flag is used, the others are ignored.", resourceName))
	cmd.Flags().StringVarP(&o.output, "output", "o", "", i18n.Translate("Select the format of the output. The values supported are 'json' , 'yaml' and 'raw'. Default: 'json'."))
}

func (o *options) addIdFlag(cmd *cobra.Command, resourceName string) {
	cmd.Flags().StringVar(&o.id, "id", "", i18n.TranslateWithArgs("Identifier of the %s.", resourceName))
}

func (o *options) addPaginationFlags(cmd *cobra.Command, _ string) {
	cmd.Flags().IntVar(&o.limit, "limit", 0, i18n.Translate("Return large lists in chunks."))
	cmd.Flags().IntVar(&o.page, "page", 0, i18n.Translate("Return a specific page of results. This is relevant for large lists and is usually paired with the 'limit' flag."))
}

func (o *options) addSortFlags(cmd *cobra.Command, _ string) {
	cmd.Flags().StringVar(&o.sort, "sort", "", i18n.Translate("Choose the property by which lists should be sorted."))
}

func (o *options) addSearchFlags(cmd *cobra.Command, _ string) {
	cmd.Flags().StringVar(&o.search, "search", "", i18n.Translate("Specify the search criteria to fetch lists."))
}

func (o *options) addCountFlags(cmd *cobra.Command, _ string) {
	cmd.Flags().StringVar(&o.count, "count", "", i18n.Translate("Specify the count to fetch lists."))
}

//func (o *options) addPropertiesFlags(cmd *cobra.Command, _ string) {
//	cmd.Flags().StringVar(&o.properties, "props", "", i18n.Translate("Request for specific resource properties, rather than the entire resource object."))
//}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return errorsx.G11NError("Resource type is required.")
	}

	o.resource = args[0]
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	return nil
}
