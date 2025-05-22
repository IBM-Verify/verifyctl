package replace

import (
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
	personalCertMessagePrefix = "UpdatePersonalCert"
	personalCertEntitlements  = "Manage Personal Certs"
	personalCertResourceName  = "personalCert"
)

var (
	personalCertShortDesc = cmdutil.TranslateShortDesc(personalCertMessagePrefix, "Update a personal certificate resource.")

	personalCertLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(personalCertMessagePrefix, `
		Update a personal certificate resource.
		Resources managed on Verify require specific entitlements, so ensure that the application or API client used with the 'auth' command is configured with the appropriate entitlements.
		An empty resource file can be generated using: verifyctl replace personalCert --boilerplate
		You can identify the entitlement required by running: verifyctl replace personalCert --entitlements`))

	personalCertExamples = templates.Examples(cmdutil.TranslateExamples(personalCertMessagePrefix, `
		# Generate an empty personalCert resource template
		verifyctl replace personalCert --boilerplate
		# Update a personal certificate from a YAML file
		verifyctl replace -f=./personal_cert.yaml
	`))
)

type personalCertOptions struct {
	options
	config *config.CLIConfig
}

func NewPersonalCertCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &personalCertOptions{
		config: config,
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
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
		cmdutil.WriteString(cmd, entitlementsMessage+" "+personalCertEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "PersonalCert",
			APIVersion: "1.0",
			Data: &security.PersonalCert{
				Label: "<label>",
			},
		}
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updatePersonalCert(cmd)
}

func (o *personalCertOptions) updatePersonalCert(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}
	return o.updatePersonalCertWithData(cmd, b)
}

func (o *personalCertOptions) updatePersonalCertWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)
	personalCert := &security.PersonalCert{}
	if err := yaml.Unmarshal(data, &personalCert); err != nil {
		vc.Logger.Errorf("unable to unmarshal the personalCert; err=%v", err)
		return err
	}

	client := security.NewPersonalCertClient()
	if err := client.UpdatePersonalCert(ctx, personalCert); err != nil {
		vc.Logger.Errorf("unable to update the personal certificate; err=%v, personalCert=%+v", err, personalCert)
		return err
	}

	cmdutil.WriteString(cmd, "Personal Certificate updated successfully")
	return nil
}

func (o *personalCertOptions) updatePersonalCertFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)
	personalCert := &security.PersonalCert{}
	b, err := yaml.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := yaml.Unmarshal(b, personalCert); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a personal certificate; err=%v", err)
		return err
	}

	client := security.NewPersonalCertClient()
	if err := client.UpdatePersonalCert(ctx, personalCert); err != nil {
		vc.Logger.Errorf("unable to update personal certificate; err=%v, personalCert=%+v", err, personalCert)
		return err
	}

	cmdutil.WriteString(cmd, "Resource updated")
	return nil
}
