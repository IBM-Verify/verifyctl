package replace

import (
	"fmt"
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
	applicationMessagePrefix = "UpdateApplication"
	applicationEntitlements  = "ManageApplications"
	applicationResourceName  = "application"
)

var (
	applicationShortDesc = cmdutil.TranslateShortDesc(applicationMessagePrefix, "Update Application resource.")
	applicationLongDesc  = templates.LongDesc(cmdutil.TranslateLongDesc(applicationMessagePrefix, `
        Update an Application resource. Resources managed on Verify require specific entitlements, so ensure that the application or API client used
		with the 'auth' command is configured with the appropriate entitlements. 

		An empty resource file can be generated using:

            verifyctl replace application --boilerplate

        You can identify the entitlement required by running:

            verifyctl replace application --entitlements`))
	applicationExamples = templates.Examples(cmdutil.TranslateExamples(applicationMessagePrefix, `
        # Generate an empty application resource template
        verifyctl replace application --boilerplate
		
        # Update an application from a YAML file
        verifyctl replace application -f=./application.yml`))
)

type applicationOptions struct {
	options

	config *config.CLIConfig
}

func newApplicationCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &applicationOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   applicationUsage,
		Short:                 applicationShortDesc,
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the YAML file containing updated application data."))
}

func (o *applicationOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *applicationOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *applicationOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+applicationEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Application",
			APIVersion: "1.0",
			Data: &applications.Application{
				TemplateID: "<templateId>",
				Name:       "<name>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateApplication(cmd)
}

func (o *applicationOptions) updateApplication(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateApplicationWithData(cmd, b)
}

func (o *applicationOptions) updateApplicationWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	resourceObj := &resource.ResourceObject{}
	if err := yaml.Unmarshal(data, resourceObj); err != nil {
		vc.Logger.Errorf("unable to unmarshal YAML to resource object; err=%v", err)
		return err
	}
	application, ok := resourceObj.Data.(*applications.Application)
	if !ok {
		appData, err := yaml.Marshal(resourceObj.Data)
		if err != nil {
			vc.Logger.Errorf("unable to marshal resource data; err=%v", err)
			return err
		}
		application = &applications.Application{}
		if err := yaml.Unmarshal(appData, application); err != nil {
			vc.Logger.Errorf("unable to unmarshal data to Application; err=%v", err)
			return err
		}
	}
	if application.Name == "" {
		vc.Logger.Errorf("application name is missing in YAML")
		return fmt.Errorf("application name is missing in YAML")
	}
	client := applications.NewApplicationClient()
	if err := client.UpdateApplication(ctx, application); err != nil {
		vc.Logger.Errorf("unable to update the application; err=%v, application=%+v", err, application)
		return err
	}
	cmdutil.WriteString(cmd, "Application updated successfully")
	return nil
}

func (o *applicationOptions) updateApplicationFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	application := &applications.Application{}
	b, err := yaml.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := yaml.Unmarshal(b, application); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an Application; err=%v", err)
		return err
	}

	client := applications.NewApplicationClient()
	if err := client.UpdateApplication(ctx, application); err != nil {
		vc.Logger.Errorf("unable to update the Application; err=%v, application=%+v", err, application)
		return err
	}

	cmdutil.WriteString(cmd, "Application updated successfully")
	return nil
}
