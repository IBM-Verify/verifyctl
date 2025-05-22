package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	personalCertUsage         = `personalCert [options]`
	personalCertMessagePrefix = "DeletePersonalCert"
	personalCertEntitlements  = "Manage Personal Certs"
	personalCertResourceName  = "personalCert"
)

var (
	personalCertLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(personalCertMessagePrefix, `
		Delete a personal certificate in IBM Security Verify based on label.
		Resources managed on Verify have specific entitlements, so ensure that the application or API client used with the 'auth' command is configured with the appropriate entitlements.
		You can identify the entitlement required by running: verifyctl delete personalCert --entitlements`))

	personalCertExamples = templates.Examples(cmdutil.TranslateExamples(personalCertMessagePrefix, `
		# Delete a personal certificate by label
		verifyctl delete personalCert --personalCertLabel=certificateLabel
	`))
)

type personalCertOptions struct {
	options
	config *config.CLIConfig
	label  string
}

func NewPersonalCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &personalCertOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   personalCertUsage,
		Short:                 cmdutil.TranslateShortDesc(personalCertMessagePrefix, "Delete Verify personal certificate based on a label."),
		Long:                  personalCertLongDesc,
		Example:               personalCertExamples,
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

func (o *personalCertOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.label, "personalCertLabel", o.label, i18n.Translate("Label of the personal certificate to delete. (Required)"))
}

func (o *personalCertOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *personalCertOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}
	calledAs := cmd.CalledAs()
	if calledAs == "personalCert" && o.label == "" {
		return errorsx.G11NError(i18n.Translate("The 'name' flag is required to delete a personal certificate"))
	}
	return nil
}

func (o *personalCertOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+" "+personalCertEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "personalCert" || len(o.label) > 0 {
		return o.handleSinglePersonalCert(cmd, args)
	}
	return nil
}

func (o *personalCertOptions) handleSinglePersonalCert(cmd *cobra.Command, _ []string) error {
	c := security.NewPersonalCertClient()
	err := c.DeletePersonalCert(cmd.Context(), o.label)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.label)
	return nil
}
