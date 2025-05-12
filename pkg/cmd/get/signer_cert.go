package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	signerCertUsage         = `signerCerts [flags]`
	signerCertMessagePrefix = "GetSignerCerts"
	signerCertEntitlements  = "Manage Signer Certs"
	signerCertResourceName  = "signerCert"
)

var (
	signerCertLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(signerCertMessagePrefix, `
		Get Verify Signer certificate based on an optional filter or a specific Signer certificate.

		Resources managed on Verify have specific entitlements, so ensure that the application or API client used with the 'auth' command is configured with the appropriate entitlements.

		You can identify the entitlement required by running: verifyctl get signerCert --entitlements`))

	signerCertExamples = templates.Examples(cmdutil.TranslateExamples(signerCertMessagePrefix, `
		# Get a specific Signer certificate by lable
		verifyctl get signerCert -o=yaml --name=testsignerCert

		# Get 10 policies based on a given search criteria and sort it in the ascending order by name.
		verifyctl get Signer-certificate --count=2 --sort=label -o=yaml
		`))
)

type signerCertOptions struct {
	options
	config *config.CLIConfig
	label  string
}

func newSignerCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &signerCertOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   signerCertUsage,
		Short:                 cmdutil.TranslateShortDesc(signerCertMessagePrefix, "Get Verify Signer certificates based on an optional filter or a specific certificate."),
		Long:                  signerCertLongDesc,
		Example:               signerCertExamples,
		Aliases:               []string{"signerCert"},
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
	o.addCommonFlags(cmd, signerCertResourceName)
	cmd.Flags().StringVar(&o.label, "signerCertLabel", o.label, i18n.Translate("signerCertName to get details"))
	o.addSortFlags(cmd, signerCertResourceName)
	o.addCountFlags(cmd, signerCertResourceName)
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
		return errorsx.G11NError(i18n.Translate("'signerCertName' flag is required."))
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
	return o.handleSignerCertList(cmd, args)
}

func filterSignerCertData(scrt *security.SignerCert, includeCert bool) map[string]interface{} {
	data := map[string]interface{}{

		"notbefore":           scrt.NotBefore,
		"subject":             scrt.Subject,
		"notafter":            scrt.NotAfter,
		"serial_number":       scrt.SerialNumber,
		"label":               scrt.Label,
		"version":             scrt.Version,
		"issuer":              scrt.Issuer,
		"isDefault":           scrt.IsDefault,
		"keysize":             scrt.KeySize,
		"signature_algorithm": scrt.SignatureAlgorithm,
	}
	if includeCert {
		data["cert"] = scrt.Cert
	}
	return data
}

func (o *signerCertOptions) handleSingleSignerCert(cmd *cobra.Command, _ []string) error {
	c := security.NewSignerCertClient()
	scrt, uri, err := c.GetSignerCert(cmd.Context(), o.label)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, scrt, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "SignerCert",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			Name: scrt.Label,
			URI:  uri,
		},
		Data: filterSignerCertData(scrt, true),
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}
	return nil
}

func (o *signerCertOptions) handleSignerCertList(cmd *cobra.Command, _ []string) error {
	c := security.NewSignerCertClient()
	scrts, uri, err := c.GetSignerCerts(cmd.Context(), o.sort, o.count)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, scrts, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, scrt := range scrts.SignerCerts {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "SignerCert",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				Name: scrt.Label,
			},
			Data: filterSignerCertData(&scrt, false),
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI: uri,
		},
		Items: items,
	}

	if o.output == "raw" || o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}
	return nil
}
