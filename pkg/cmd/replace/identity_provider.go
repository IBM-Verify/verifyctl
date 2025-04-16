package replace

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/module"
	"github.com/ibm-verify/verifyctl/pkg/module/directory"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	identitysourceUsage         = `identitysource [options]`
	identitysourceMessagePrefix = "UpdateIdentitysource"
	identitysourceEntitlements  = "Manage identitysources"
	identitysourceResourceName  = "identitysource"
)

var (
	identitysourceShortDesc = cmdutil.TranslateShortDesc(identitysourceMessagePrefix, "Update a identitysource resource.")

	identitysourceLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identitysourceMessagePrefix, `
		Update a identitysource resource.

Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl replace identitysource --boilerplate

You can identify the entitlement required by running:

  verifyctl replace identitysource --entitlements`))

	identitysourceExamples = templates.Examples(cmdutil.TranslateExamples(identitysourceMessagePrefix, `
		# Generate an empty identitysource resource template
		verifyctl replace identitysource --boilerplate

		# Update a identitysource from a JSON file
		verifyctl replace identitysource -f=./identitysource-12345.json`))
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *identitysourceOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identitysourceOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return module.MakeSimpleError(i18n.Translate("'file' option is required if no other options are used."))
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
			Data: &directory.IdentitySource{
				InstanceName: "<InstanceName>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.updateIdentitysource(cmd, auth)
}

func (o *identitysourceOptions) updateIdentitysource(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateIdentitysourceWithData(cmd, auth, b)
}

func (o *identitysourceOptions) updateIdentitysourceWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to identitysource object
	identitysource := &directory.IdentitySource{}
	if err := json.Unmarshal(data, &identitysource); err != nil {
		vc.Logger.Errorf("unable to unmarshal the identitysource; err=%v", err)
		return err
	}

	client := directory.NewIdentitySourceClient()
	if err := client.UpdateIdentitysource(ctx, auth, identitysource); err != nil {
		vc.Logger.Errorf("unable to update the identitysource; err=%v, identitysource=%+v", err, identitysource)
		return err
	}

	cmdutil.WriteString(cmd, "Identitysource updated successfully")
	return nil
}

func (o *identitysourceOptions) updateIdentitysourceFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to identitysource object
	identitysource := &directory.IdentitySource{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, identitysource); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a identitysource; err=%v", err)
		return err
	}

	client := directory.NewIdentitySourceClient()
	if err := client.UpdateIdentitysource(ctx, auth, identitysource); err != nil {
		vc.Logger.Errorf("unable to update the identitysource; err=%v, identitysource=%+v", err, identitysource)
		return err
	}

	cmdutil.WriteString(cmd, "Identitysource updated successfully")
	return nil
}
