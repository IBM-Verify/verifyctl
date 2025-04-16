package set

import (
	"io"

	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/module"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usage         = "set [resource-type] [flags]"
	messagePrefix = "Set"
)

var (
	longDesc = templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `
		Update a Verify managed resource, such as an application, user, API client etc.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl set [resource-type] --entitlements
  
The flags supported by each resource type may differ and can be determined using:

  verifyctl set [resource-type] -h`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Set an application and write it to a file
		verifyctl set application --file ./app-1098012.yaml`))

	entitlementsMessage = i18n.Translate("Choose any of the following entitlements to configure your application or API client:\n")
)

type options struct {
	resourceType string
	format       string
	file         string
	entitlements bool
	id           string

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter, groupID string) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 cmdutil.TranslateShortDesc(messagePrefix, "Set a Verify managed resource."),
		Long:                  longDesc,
		Example:               examples,
		DisableFlagsInUseLine: true,
		Aliases:               []string{"put", "update"},
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
	cmd.AddCommand(newThemesCommand(config, streams))

	return cmd
}

func (o *options) addCommonFlags(cmd *cobra.Command, resourceName string) {
	cmd.Flags().BoolVar(&o.entitlements, "entitlements", o.entitlements, i18n.Translate("List the entitlements that can be configured to grant access to the resource. This is useful to know what to configure on the application or API client used to generate the login token. When this flag is used, the others are ignored."))
	cmd.Flags().StringVar(&o.format, "format", "", i18n.Translate("Select the format of the input data. The values supported are 'json',  'yaml' and 'raw'. Default: yaml"))
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. If the file has an appropriate extension, the format of the output can be determined without needing to provide the '--format' flag."))
	cmd.Flags().StringVar(&o.id, "id", "", i18n.TranslateWithArgs("Identifier of the %s.", resourceName))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return module.MakeSimpleError(i18n.Translate("Resource type is required."))
	}

	o.resourceType = args[0]
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	return nil
}
