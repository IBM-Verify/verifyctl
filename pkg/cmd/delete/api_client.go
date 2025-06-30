package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	apiclientUsage         = `apiclient [flags]`
	apiclientMessagePrefix = "DeleteApiclient"
	apiclientEntitlements  = "Manage apiclients"
	apiclientResourceName  = "apiclient"
)

var (
	apiclientLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(apiclientMessagePrefix, `
		Delete API client based on clientName.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete apiclient --entitlements`))

	apiclientExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an API client by name
		verifyctl delete apiclient --clientName="clientName",

		# Delete an API client by ID
		verifyctl delete apiclient --clientID="12345"`,
	))
)

type apiclientsOptions struct {
	options
	id     string
	config *config.CLIConfig
}

func NewAPIClientCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &apiclientsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   apiclientUsage,
		Short:                 cmdutil.TranslateShortDesc(apiclientMessagePrefix, "Delete API client based on its name or id."),
		Long:                  apiclientLongDesc,
		Example:               apiclientExamples,
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
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.id, "clientID", o.id, i18n.Translate("clientID to be deleted"))
}

func (o *apiclientsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *apiclientsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "apiclient" && o.id == "" {
		return errorsx.G11NError("'clientId' flag is required")
	}
	return nil
}

func (o *apiclientsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+apiclientEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "apiclient" {
		return o.handleSingleAPIClient(cmd, args)
	}
	return nil
}

func (o *apiclientsOptions) handleSingleAPIClient(cmd *cobra.Command, _ []string) error {
	c := security.NewAPIClient()
	var id string
	var err error

	if o.id != "" {
		id = o.id
		err = c.DeleteAPIClientById(cmd.Context(), id)
		if err != nil {
			return err
		}
	} else {
		return errorsx.G11NError("either clientName or clientId must be provided")
	}

	resourceIdentifier := o.id
	cmdutil.WriteString(cmd, "Resource deleted with ID: "+resourceIdentifier)
	return nil
}
