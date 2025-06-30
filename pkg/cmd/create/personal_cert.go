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
	personalCertUsage         = `personalCert [options]`
	personalCertMessagePrefix = "CreatepersonalCert"
	personalCertEntitlements  = "Manage personal certificates"
	personalCertResourceName  = "personalCert"
)

var (
	personalCertShortDesc = cmdutil.TranslateShortDesc(
		personalCertMessagePrefix,
		"Create a personal certificate with specified options.",
	)
	personalCertLongDesc = templates.LongDesc(
		cmdutil.TranslateLongDesc(
			personalCertMessagePrefix,
			`Create a personal certificate resource. Resources managed on Verify require specific entitlements.
			 Ensure the application or API client used with the 'auth' command has the "Manage personal certificates" entitlement. 
			 Generate an empty resource file with: verifyctl create personalCert --boilerplate
			Check required entitlements with: verifyctl create personalCert --entitlements
			Input files can be in YAML or JSON format.`,
		),
	)
	personalCertExamples = templates.Examples(
		cmdutil.TranslateExamples(
			personalCertMessagePrefix,
			`# Create an empty personal certificate resource.
		verifyctl create personalCert --boilerplate
		# Create a personal certificate using a YAML file.
		verifyctl create -f=./personal_cert.yaml
		# Create a personal certificate using a JSON file.
	verifyctl create -f=./personal_cert.json`,
		),
	)
)

type personalCertOptions struct {
	options
	file string
}

func newPersonalCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &personalCertOptions{
		options: options{
			config: config,
		},
	}

	cmd := &cobra.Command{
		Use:                   personalCertUsage,
		Short:                 personalCertShortDesc,
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
	o.addCommonFlags(cmd, personalCertResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the YAML file that contains the input data."))
}

func (o *personalCertOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *personalCertOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *personalCertOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+personalCertEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "PersonalCert",
			APIVersion: "1.0",
			Data:       &security.PersonalCert{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createPersonalCert(cmd)
}

func (o *personalCertOptions) createPersonalCert(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createPersonalCertWithData(cmd, b)
}

func (o *personalCertOptions) createPersonalCertWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	personalCert := &security.PersonalCert{}
	if err := yaml.Unmarshal(data, &personalCert); err != nil {
		vc.Logger.Errorf("unable to unmarshal the personalCert; err=%v", err)
		return err
	}

	client := security.NewPersonalCertClient()
	resourceURI, err := client.CreatePersonalCert(ctx, personalCert)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *personalCertOptions) createPersonalCertFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	personalCert := &security.PersonalCert{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map into json; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, personalCert); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an personalCert; err=%v", err)
		return err
	}

	client := security.NewPersonalCertClient()
	resourceURI, err := client.CreatePersonalCert(ctx, personalCert)
	if err != nil {
		vc.Logger.Errorf("unable to create the personal certificate; err=%v, personalCert=%+v", err, personalCert)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
