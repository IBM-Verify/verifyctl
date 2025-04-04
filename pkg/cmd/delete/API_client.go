package delete

import (
	"io"

	"github.com/spf13/cobra"
	"github.ibm.com/sec-ci/devops-experiments/pkg/config"
	"github.ibm.com/sec-ci/devops-experiments/pkg/i18n"
	"github.ibm.com/sec-ci/devops-experiments/pkg/module"
	"github.ibm.com/sec-ci/devops-experiments/pkg/module/directory"
	cmdutil "github.ibm.com/sec-ci/devops-experiments/pkg/util/cmd"
	"github.ibm.com/sec-ci/devops-experiments/pkg/util/templates"
)

const (
	apiclientUsage         = `apiclient [flags]`
	apiclientMessagePrefix = "DeleteApiclient"
	apiclientEntitlements  = "Manage apiclients"
	apiclientResourceName  = "apiclient"
)

var (
	apiclientLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(apiclientMessagePrefix, `
		Delete Verify API client based on clientName.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete apiclient --entitlements`))

	apiclientExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an API client
		verifyctl delete apiclient --clientName="clientName"`,
	))
)

type apiclientsOptions struct {
	options

	config *config.CLIConfig
}

func NewAPIclientCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &apiclientsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   apiclientUsage,
		Short:                 cmdutil.TranslateShortDesc(apiclientMessagePrefix, "Delete Verify API client based on an id."),
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
		return module.MakeSimpleError(i18n.Translate("'clientName' flag is required"))
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
		return o.handleSingleApiClient(cmd, auth, args)
	}
	return nil
}

func (o *apiclientsOptions) handleSingleApiClient(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewApiClient()
	err := c.DeleteApiclient(cmd.Context(), auth, o.name)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.name)
	return nil
}
