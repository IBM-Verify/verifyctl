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
	signerCertUsage         = `signerCert [options]`
	signerCertMessagePrefix = "DeleteSignerCert"
	signerCertEntitlements  = "Manage Signer Certs"
	signerCertResourceName  = "signerCert"
)

var (
	signerCertLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(signerCertMessagePrefix, `
		Delete a signer certificate in IBM Security Verify based on label.
		Resources managed on Verify have specific entitlements, so ensure that the application or API client used with the 'auth' command is configured with the appropriate entitlements.
		You can identify the entitlement required by running: verifyctl delete signerCert --entitlements`))

	signerCertExamples = templates.Examples(cmdutil.TranslateExamples(signerCertMessagePrefix, `
		# Delete a signer certificate by label
		verifyctl delete signerCert --signerCertLabel "certificateLabel"
	`))
)

type signerCertOptions struct {
	options
	config *config.CLIConfig
	label  string
}

func NewSignerCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &signerCertOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   signerCertUsage,
		Short:                 cmdutil.TranslateShortDesc(signerCertMessagePrefix, "Delete Verify signer certificate based on a label."),
		Long:                  signerCertLongDesc,
		Example:               signerCertExamples,
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

func (o *signerCertOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.label, "signerCertLabel", o.label, i18n.Translate("Label of the signer certificate to delete. (Required)"))
}

func (o *signerCertOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *signerCertOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}
	calledAs := cmd.CalledAs()
	if calledAs == "signerCert" && o.label == "" {
		return errorsx.G11NError(i18n.Translate("The 'name' flag is required to delete a signer certificate"))
	}
	return nil
}

func (o *signerCertOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+" "+signerCertEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "signerCert" || len(o.label) > 0 {
		return o.handleSingleSignerCert(cmd, args)
	}
	return nil
}

func (o *signerCertOptions) handleSingleSignerCert(cmd *cobra.Command, _ []string) error {
	c := security.NewSignerCertClient()
	err := c.DeleteSignerCert(cmd.Context(), o.label)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.label)
	return nil
}
