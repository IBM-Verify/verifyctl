package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	signerCertUsage         = `signerCert [options]`
	signerCertMessagePrefix = "CreatesignerCert"
	signerCertEntitlements  = "Manage signer certificates"
	signerCertResourceName  = "signerCert"
)

var (
	signerCertShortDesc = cmdutil.TranslateShortDesc(
		signerCertMessagePrefix,
		"Create a signer certificate with specified options.",
	)
	signerCertLongDesc = templates.LongDesc(
		cmdutil.TranslateLongDesc(
			signerCertMessagePrefix,
			`Create a signer certificate resource. Resources managed on Verify require specific entitlements.
			 Ensure the application or API client used with the 'auth' command has the "Manage signer certificates" entitlement. 
			 Generate an empty resource file with: verifyctl create signerCert --boilerplate
			Check required entitlements with: verifyctl create signerCert --entitlements
			Input files can be in YAML or JSON format.`,
		),
	)
	signerCertExamples = templates.Examples(
		cmdutil.TranslateExamples(
			signerCertMessagePrefix,
			`# Create an empty signer certificate resource.
		verifyctl create signerCert --boilerplate
		# Create a signer certificate using a YAML file.
		verifyctl create signerCert -f=./signer_cert.yaml
		# Create a signer certificate using a JSON file.
	verifyctl create signerCert -f=./signer_cert.json`,
		),
	)
)

type signerCertOptions struct {
	options
	file string
}

func newSignerCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &signerCertOptions{
		options: options{
			config: config,
		},
	}

	cmd := &cobra.Command{
		Use:                   signerCertUsage,
		Short:                 signerCertShortDesc,
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
	o.addCommonFlags(cmd, signerCertResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the YAML file that contains the input data."))
}

func (o *signerCertOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *signerCertOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *signerCertOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+signerCertEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "SignerCert",
			APIVersion: "1.0",
			Data:       &security.SignerCert{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createSignerCert(cmd)
}

func (o *signerCertOptions) createSignerCert(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createSignerCertWithData(cmd, b)
}

func (o *signerCertOptions) createSignerCertWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	signerCert := &security.SignerCert{}
	if err := yaml.Unmarshal(data, &signerCert); err != nil {
		vc.Logger.Errorf("unable to unmarshal the signerCert; err=%v", err)
		return err
	}

	client := security.NewSignerCertClient()
	resourceURI, err := client.CreateSignerCert(ctx, signerCert)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *signerCertOptions) createSignerCertFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	signerCert := &security.SignerCert{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map into json; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, signerCert); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an signerCert; err=%v", err)
		return err
	}

	client := security.NewSignerCertClient()
	resourceURI, err := client.CreateSignerCert(ctx, signerCert)
	if err != nil {
		vc.Logger.Errorf("unable to create the signer certificate; err=%v, signerCert=%+v", err, signerCert)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
