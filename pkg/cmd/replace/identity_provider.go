package replace

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	identitySourceUsage         = `identitysource [options]`
	identitySourceMessagePrefix = "UpdateIdentitySource"
	identitySourceEntitlements  = "Manage identitySources"
	identitySourceResourceName  = "identitysource"
)

var (
	identitySourceShortDesc = cmdutil.TranslateShortDesc(identitySourceMessagePrefix, "Update a identitySource resource.")

	identitySourceLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitySourceMessagePrefix, `
		Update a identitySource resource.

Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl replace identitysource --boilerplate

You can identify the entitlement required by running:

  verifyctl replace identitysource --entitlements`))

	identitySourceExamples = templates.Examples(cmdutil.TranslateExamples(identitySourceMessagePrefix, `
		# Generate an empty identitySource resource template
		verifyctl replace identitysource --boilerplate

		# Update a identitySource from a JSON file
		verifyctl replace identitysource --identitySourceID "1234" -f "identitySource.yaml"`))
)

type identitySourceOptions struct {
	options
	identitySourceID string
	config           *config.CLIConfig
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
		SilenceUsage:          true,
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
	cmd.Flags().StringVar(&o.identitySourceID, "identitySourceID", o.identitySourceID, i18n.Translate("identitySourceID to delete"))
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *identitySourceOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitySourceOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("'file' option is required if no other options are used.")
	}
	calledAs := cmd.CalledAs()
	if calledAs == "identitysource" && o.identitySourceID == "" {
		return errorsx.G11NError(i18n.Translate("'identitySourceID' flag is required."))
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
			Data: &authentication.IdentitySource{
				InstanceName: "<InstanceName>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateIdentitySource(cmd)
}

func (o *identitySourceOptions) updateIdentitySource(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateIdentitySourceWithData(cmd, b)
}

func (o *identitySourceOptions) updateIdentitySourceWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to identitySource object
	resourceObj := &resource.ResourceObject{}
	if err := yaml.Unmarshal(data, resourceObj); err != nil {
		vc.Logger.Errorf("unable to unmarshal YAML to resource object; err=%v", err)
		return err
	}
	identitySource, ok := resourceObj.Data.(*authentication.IdentitySource)
	if !ok {
		appData, err := yaml.Marshal(resourceObj.Data)
		if err != nil {
			vc.Logger.Errorf("unable to marshal resource data; err=%v", err)
			return err
		}
		identitySource = &authentication.IdentitySource{}
		if err := yaml.Unmarshal(appData, identitySource); err != nil {
			vc.Logger.Errorf("unable to unmarshal data to Application; err=%v", err)
			return err
		}
	}

	client := authentication.NewIdentitySourceClient()
	if err := client.UpdateIdentitySource(ctx, o.identitySourceID, identitySource); err != nil {
		vc.Logger.Errorf("unable to update the Identity Source err=%v, identitySource=%+v", err, identitySource)
		return err
	}
	cmdutil.WriteString(cmd, "IdentitySource updated successfully")
	return nil
}

func (o *identitySourceOptions) updateIdentitySourceFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to identitySource object
	identitySource := &authentication.IdentitySource{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, identitySource); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a Identity Source err=%v", err)
		return err
	}

	client := authentication.NewIdentitySourceClient()
	if err := client.UpdateIdentitySource(ctx, "", identitySource); err != nil {
		vc.Logger.Errorf("unable to update the Identity Source err=%v, identitySource=%+v", err, identitySource)
		return err
	}

	cmdutil.WriteString(cmd, "IdentitySource updated successfully")
	return nil
}
