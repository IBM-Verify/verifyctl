package replace

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	apiclientUsage         = `apiclient [options]`
	apiclientMessagePrefix = "UpdateApiclient"
	apiclientEntitlements  = "manageAPIClients"
	apiclientResourceName  = "apiclient"
)

var (
	apiclientShortDesc = cmdutil.TranslateShortDesc(apiclientMessagePrefix, "Update an API client resource.")
	apiclientLongDesc  = templates.LongDesc(cmdutil.TranslateLongDesc(apiclientMessagePrefix, `
        Update an API client resource. Resources managed on Verify require specific entitlements, so ensure that the application or API client used
		with the 'auth' command is configured with the appropriate entitlements. 

		An empty resource file can be generated using:

            verifyctl replace apiclient --boilerplate

        You can identify the entitlement required by running:

            verifyctl replace apiclient --entitlements`))
	apiclientExamples = templates.Examples(cmdutil.TranslateExamples(apiclientMessagePrefix, `
        # Generate an empty apiclient resource template
        verifyctl replace apiclient --boilerplate
		
        # Update an apiclient from a YAML file
        verifyctl replace apiclient -f=./apiclient.yml`))
)

type apiclientOptions struct {
	options

	config *config.CLIConfig
}

func newAPIClientCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &apiclientOptions{
		config: config,
	}
	cmd := &cobra.Command{
		Use:                   apiclientUsage,
		Short:                 apiclientShortDesc,
		Long:                  apiclientLongDesc,
		Example:               apiclientExamples,
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

func (o *apiclientOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, apiclientResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the YAML file containing updated API client data."))
}

func (o *apiclientOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *apiclientOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required if no other options are used.")
	}
	return nil
}

func (o *apiclientOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+apiclientEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "APIClient",
			APIVersion: "1.0",
			Data: &security.Client{
				ID:         "<id>",
				ClientName: "<clientName>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateAPIClient(cmd)
}

func (o *apiclientOptions) updateAPIClient(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateAPIClientWithData(cmd, b)
}

func (o *apiclientOptions) updateAPIClientWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to api client object
	apiclient := &security.APIClientConfig{}
	if err := json.Unmarshal(data, &apiclient); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an API client; err=%v", err)
		return err
	}

	client := security.NewAPIClient()
	if err := client.UpdateAPIClient(ctx, apiclient); err != nil {
		vc.Logger.Errorf("unable to update the API client; err=%v, apiclient=%+v", err, apiclient)
		return err
	}

	cmdutil.WriteString(cmd, "API client updated successfully")
	return nil
}

func (o *apiclientOptions) updateAPIClientFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	apiclient := &security.APIClientConfig{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, apiclient); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a API client; err=%v", err)
		return err
	}
	client := security.NewAPIClient()
	if err := client.UpdateAPIClient(ctx, apiclient); err != nil {
		vc.Logger.Errorf("unable to update the API client; err=%v, apiclient=%+v", err, apiclient)
		return err
	}

	cmdutil.WriteString(cmd, "API client updated successfully")
	return nil
}
