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
	personalCertUsage         = `personalCerts [flags]`
	personalCertMessagePrefix = "GetPersonalCerts"
	personalCertEntitlements  = "Manage Personal Certs"
	personalCertResourceName  = "personalCert"
)

var (
	personalCertLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(personalCertMessagePrefix, `
		Get Verify personal certificate based on an optional filter or a specific personal certificate.
 
		Resources managed on Verify have specific entitlements, so ensure that the application or API client used with the 'auth' command is configured with the appropriate entitlements.
 
		You can identify the entitlement required by running: verifyctl get personalCert --entitlements`))

	personalCertExamples = templates.Examples(cmdutil.TranslateExamples(personalCertMessagePrefix, `
		# Get a specific personal certificate by lable
		verifyctl get personalCert -o=yaml --name=testpersonalCert
 
		# Get 10 policies based on a given search criteria and sort it in the ascending order by name.
		verifyctl get personal-certificate --count=2 --sort=label -o=yaml
		`))
)

type personalCertOptions struct {
	options
	config *config.CLIConfig
	label  string
}

func newPersonalCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &personalCertOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   personalCertUsage,
		Short:                 cmdutil.TranslateShortDesc(personalCertMessagePrefix, "Get Verify personal certificates based on an optional filter or a specific certificate."),
		Long:                  personalCertLongDesc,
		Example:               personalCertExamples,
		Aliases:               []string{"personalCert"},
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
	o.addCommonFlags(cmd, personalCertResourceName)
	cmd.Flags().StringVar(&o.label, "personalCertLabel", o.label, i18n.Translate("personalCertName to get details"))
	o.addSortFlags(cmd, personalCertResourceName)
	o.addCountFlags(cmd, personalCertResourceName)
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
		return errorsx.G11NError(i18n.Translate("'personalCertName' flag is required."))
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
	return o.handlePersonalCertList(cmd, args)
}

func filterPersonalCertData(pcrt *security.PersonalCert, includeCert bool) map[string]interface{} {
	data := map[string]interface{}{

		"notbefore":           pcrt.Notbefore,
		"subject":             pcrt.Subject,
		"notafter":            pcrt.Notafter,
		"serial_number":       pcrt.SerialNumber,
		"label":               pcrt.Label,
		"isDefault":           pcrt.IsDefault,
		"version":             pcrt.Version,
		"issuer":              pcrt.Issuer,
		"keysize":             pcrt.KeySize,
		"signature_algorithm": pcrt.SignatureAlgorithm,
	}
	if includeCert {
		data["cert"] = pcrt.Cert
	}
	return data
}

func (o *personalCertOptions) handleSinglePersonalCert(cmd *cobra.Command, _ []string) error {
	c := security.NewPersonalCertClient()
	pcrt, uri, err := c.GetPersonalCert(cmd.Context(), o.label)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, pcrt, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "PersonalCert",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			Name: pcrt.Label,
			URI:  uri,
		},
		Data: filterPersonalCertData(pcrt, true),
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}
	return nil
}

func (o *personalCertOptions) handlePersonalCertList(cmd *cobra.Command, _ []string) error {
	c := security.NewPersonalCertClient()
	pcrts, uri, err := c.GetPersonalCerts(cmd.Context(), o.sort, o.count)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, pcrts, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, pcrt := range pcrts.PersonalCerts {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "PersonalCert",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				Name: pcrt.Label,
			},
			Data: filterPersonalCertData(&pcrt, false),
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
