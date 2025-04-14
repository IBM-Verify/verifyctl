package delete

import (
	"fmt"
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/security"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
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
		verifyctl delete apiclient --clientId="12345"`,
	))
)

type apiclientsOptions struct {
	options
	id string

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
	cmd.Flags().StringVar(&o.name, "clientName", o.name, i18n.Translate("clientName to be deleted"))
	cmd.Flags().StringVar(&o.id, "clientId", o.id, i18n.Translate("clientId to be deleted"))
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
		return module.MakeSimpleError(i18n.Translate("either 'clientName' or 'clientId' flag is required"))
	}
	return nil
}

func (o *apiclientsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+apiclientEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "apiclient" || len(o.name) > 0 {
		// deal with single API client
		return o.handleSingleAPIClient(cmd, auth, args)
	}
	return nil
}

func (o *apiclientsOptions) handleSingleAPIClient(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {
	c := security.NewAPIClient()
	var id string
	var err error

	if o.id != "" {
		if o.name != "" {
			config.GetVerifyContext(cmd.Context()).Logger.Warnf("Both clientName and clientId are provided; using clientId")
		}
		id = o.id
	} else if o.name != "" {
		id, err = c.GetAPIClientId(cmd.Context(), auth, o.name)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("either clientName or clientId must be provided")
	}

	err = c.DeleteAPIClientById(cmd.Context(), auth, id)
	if err != nil {
		return err
	}

	resourceIdentifier := o.name
	if o.id != "" {
		resourceIdentifier = o.id
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+resourceIdentifier)
	return nil
}
