package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/applications"
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
	applicationUsage         = "application [options]"
	applicationMessagePrefix = "CreateApplication"
	applicationEntitlements  = "Manage applications"
	applicationResourceName  = "application"
)

var (
	applicationLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(applicationMessagePrefix, `
        Create a Verify Application using a file input.
        Resources managed on Verify have specific entitlements, so ensure that the application or API client used with the 'auth' command is configured with the appropriate entitlements.
        An empty resource file can be generated using: verifyctl create application --boilerplate
        You can identify the entitlement required by running: verifyctl create application --entitlements`))

	applicationExamples = templates.Examples(cmdutil.TranslateExamples(applicationMessagePrefix, `
        # Create an empty application resource. This can be piped into a file.
        verifyctl create application --boilerplate

        # Create an application using a YAML file.
        verifyctl create -f=./application.yaml`))
)

type applicationOptions struct {
	options
	applicationType string
	config          *config.CLIConfig
}

func newApplicationCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &applicationOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   applicationUsage,
		Short:                 cmdutil.TranslateShortDesc(applicationMessagePrefix, "Create a Verify Application using a file input."),
		Long:                  applicationLongDesc,
		Example:               applicationExamples,
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

func (o *applicationOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, applicationResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the yaml file containing application data"))
	cmd.Flags().StringVarP(&o.applicationType, "applicationType", "t", "", i18n.Translate("Application type [OIDC, ACLC, SAML, BOOKMARK]"))
}

func (o *applicationOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *applicationOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError(i18n.Translate("The 'file' option is required if no other options are used"))
	}

	return nil
}

func (o *applicationOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+" "+applicationEntitlements)
		return nil
	}

	if o.boilerplate {
		if o.applicationType == "saml" || o.applicationType == "oidc" || o.applicationType == "aclc" || o.applicationType == "bookmark" || o.applicationType == "" {
			resourceObj := &resource.ResourceObject{
				Kind:       resource.ResourceTypePrefix + "Application",
				APIVersion: "1.0",
				Data:       applications.ApplicationExample(o.applicationType),
			}
			cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
			return nil
		} else {
			return errorsx.G11NError(i18n.Translate("unknown application type"))
		}
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createApplication(cmd)
}

func (o *applicationOptions) createApplication(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createApplicationWithData(cmd, b)
}

func (o *applicationOptions) createApplicationWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	application := &applications.Application{}
	if err := yaml.Unmarshal(data, &application); err != nil {
		vc.Logger.Errorf("unable to unmarshal the application; err=%v", err)
		return err
	}

	client := applications.NewApplicationClient()
	resourceURI, err := client.CreateApplication(ctx, application)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *applicationOptions) createApplicationFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	application := &applications.Application{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, application); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an application; err=%v", err)
		return err
	}

	client := applications.NewApplicationClient()
	resourceURI, err := client.CreateApplication(ctx, application)
	if err != nil {
		vc.Logger.Errorf("unable to create the application; err=%v, application=%+v", err, application)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
