package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/module/directory"

	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	identitysourceUsage         = "identitysource [options]"
	identitysourceMessagePrefix = "CreateIdentitySource"
	identitysourceEntitlements  = "Manage identitysources"
	identitysourceResourceName  = "identitysource"
)

var (
	identitysourceShortDesc = cmdutil.TranslateShortDesc(identitysourceMessagePrefix, "Additional options to create a identitysource.")

	identitysourceLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitysourceMessagePrefix, `
		Additional options to create a identitysource.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create identitysource --boilerplate

You can identify the entitlement required by running:

	verifyctl create identitysource --entitlements`))

	identitysourceExamples = templates.Examples(cmdutil.TranslateExamples(identitysourceMessagePrefix, `
		# Create an empty identitysource resource. This can be piped into a file.
		verifyctl create identitysource --boilerplate

		# Create a identitysource using a JSON file.
		verifyctl create identitysource -f=./identitysource.json`))
)

type identitysourceOptions struct {
	options

	config *config.CLIConfig
}

func newIdentitysourceCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identitysourceOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identitysourceUsage,
		Short:                 identitysourceShortDesc,
		Long:                  identitysourceLongDesc,
		Example:               identitysourceExamples,
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

func (o *identitysourceOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, identitysourceResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the JSON file containing identitysource data.")
}

func (o *identitysourceOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitysourceOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("The 'file' option is required if no other options are used.")
	}
	return nil
}

func (o *identitysourceOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identitysourceEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "IdentitySource",
			APIVersion: "2.0",
			Data:       &directory.IdentitySource{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.createIdentitySource(cmd, auth)
}

func (o *identitysourceOptions) createIdentitySource(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	// create identitysource with data
	return o.createIdentitySourceWithData(cmd, auth, b)
}

func (o *identitysourceOptions) createIdentitySourceWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to identitysource
	identitysource := &directory.IdentitySource{}
	if err := json.Unmarshal(data, &identitysource); err != nil {
		vc.Logger.Errorf("unable to unmarshal the identitysource; err=%v", err)
		return err
	}

	client := directory.NewIdentitySourceClient()
	resourceURI, err := client.CreateIdentitysource(ctx, auth, identitysource)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *identitysourceOptions) createIdentitySourceFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to identitysource
	identitysource := &directory.IdentitySource{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, identitysource); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an identitysource; err=%v", err)
		return err
	}

	client := directory.NewIdentitySourceClient()
	resourceURI, err := client.CreateIdentitysource(ctx, auth, identitysource)
	if err != nil {
		vc.Logger.Errorf("unable to create the identitysource; err=%v, identitysource=%+v", err, identitysource)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
