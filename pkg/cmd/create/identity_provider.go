package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	"gopkg.in/yaml.v3"

	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	identitySourceUsage         = "identitysource [options]"
	identitySourceMessagePrefix = "CreateIdentitySource"
	identitySourceEntitlements  = "Manage identitySources"
	identitySourceResourceName  = "identitysource"
)

var (
	identitySourceShortDesc = cmdutil.TranslateShortDesc(identitySourceMessagePrefix, "Additional options to create a identitySource.")

	identitySourceLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitySourceMessagePrefix, `
		Additional options to create a identitySource.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create identitysource --boilerplate

You can identify the entitlement required by running:

	verifyctl create identitysource --entitlements`))

	identitySourceExamples = templates.Examples(cmdutil.TranslateExamples(identitySourceMessagePrefix, `
		# Create an empty identitySource resource. This can be piped into a file.
		verifyctl create identitysource --boilerplate

		# Create a identitySource using a YAML file.
		verifyctl create -f=./identitysource.yaml

		# Create a identitySource using a JSON file.
		verifyctl create -f=./identitysource.json`))
)

type identitySourceOptions struct {
	options

	config *config.CLIConfig
}

func newIdentitySourceCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identitySourceOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identitySourceUsage,
		Short:                 identitySourceShortDesc,
		Long:                  identitySourceLongDesc,
		Example:               identitySourceExamples,
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

func (o *identitySourceOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, identitySourceResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the JSON file containing identitySource data.")
}

func (o *identitySourceOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitySourceOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("The 'file' option is required if no other options are used.")
	}
	return nil
}

func (o *identitySourceOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identitySourceEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "IdentitySource",
			APIVersion: "2.0",
			Data:       &authentication.IdentitySource{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createIdentitySource(cmd)
}

func (o *identitySourceOptions) createIdentitySource(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createIdentitySourceWithData(cmd, b)
}

func (o *identitySourceOptions) createIdentitySourceWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	identitySource := &authentication.IdentitySource{}
	if err := yaml.Unmarshal(data, &identitySource); err != nil {
		vc.Logger.Errorf("unable to unmarshal the Identity Source err=%v", err)
		return err
	}

	client := authentication.NewIdentitySourceClient()
	resourceURI, err := client.CreateIdentitySource(ctx, identitySource)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *identitySourceOptions) createIdentitySourceFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	identitySource := &authentication.IdentitySource{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, identitySource); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an Identity Source err=%v", err)
		return err
	}

	client := authentication.NewIdentitySourceClient()
	resourceURI, err := client.CreateIdentitySource(ctx, identitySource)
	if err != nil {
		vc.Logger.Errorf("unable to create the Identity Source err=%v, identitySource=%+v", err, identitySource)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
