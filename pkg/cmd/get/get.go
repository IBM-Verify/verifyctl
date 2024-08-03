package get

import (
	"fmt"
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
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
		# Get an application and write it to a file
		verifyctl get application --outfile ./app-1098012.yaml --id=1098012

		# Get all users that match department "2A". There may be limits introduced by the API.
		verifyctl get users --filter="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq \"2A\"" --attributes="userName,emails,urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager" -o yaml`))

	entitlementsMessage = i18n.Translate("Choose any of the following entitlements to configure your application or API client:\n")
)

type options struct {
	ResourceType string
	OutputType   string
	OutputFile   string
	Entitlements bool

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
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
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)

	// add sub commands
	cmd.AddCommand(NewAttributesCommand(config, streams))

	return cmd
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&o.OutputType, "output", "o", "", i18n.Translate("Select the format of the output. The values supported are 'json' and 'yaml'. Default: yaml"))
	cmd.PersistentFlags().StringVar(&o.OutputFile, "outfile", "", i18n.Translate("Persist the output to the specified file path. The default directory is local. If the file has an appropriate extension, the format of the output can be determined without needing to provide the '--output' flag."))
	cmd.PersistentFlags().BoolVar(&o.Entitlements, "entitlements", o.Entitlements, i18n.Translate("List the entitlements that can be configured to grant access to the resource. This is useful to know what to configure on the application or API client used to generate the login token. When this flag is used, the others are ignored."))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf(i18n.Translate("Resource type is required."))
	}

	o.ResourceType = args[0]
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	return nil
}
