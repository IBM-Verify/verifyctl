package delete

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/directory"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	identitysourcesUsage         = `identitysource [flags]`
	identitysourcesMessagePrefix = "DeleteIdentitysource"
	identitysourcesEntitlements  = "Manage identitysources"
	identitysourceResourceName   = "identitysource"
)

var (
	identitysourcesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitysourcesMessagePrefix, `
		Delete Verify identitysource based on instancename.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete identitysource --entitlements`))

	identitysourcesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an identitysource
		verifyctl delete identitysource --instanceName=instanceName`,
	))
)

type identitysourcesOptions struct {
	options

	config *config.CLIConfig
}

func NewIdentitysourceCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identitysourcesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identitysourcesUsage,
		Short:                 cmdutil.TranslateShortDesc(identitysourcesMessagePrefix, "Delete Verify identitysource based on an id."),
		Long:                  identitysourcesLongDesc,
		Example:               identitysourcesExamples,
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

func (o *identitysourcesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.name, "instanceName", o.name, i18n.Translate("instanceName to be deleted"))
}

func (o *identitysourcesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitysourcesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "identitysource" && o.name == "" {
		return module.MakeSimpleError(i18n.Translate("'instanceName' flag is required."))
	}
	return nil
}

func (o *identitysourcesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identitysourcesEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "identitysource" || len(o.name) > 0 {
		// deal with single identitysource
		return o.handleSingleIdentitysource(cmd, auth, args)
	}
	return nil
}

func (o *identitysourcesOptions) handleSingleIdentitysource(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewIdentitySourceClient()
	err := c.DeleteIdentitysource(cmd.Context(), auth, o.name)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.name)
	return nil
}
