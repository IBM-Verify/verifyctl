package replace

import (
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/integrations"

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
	identityAgentUsage         = `identityagent [options]`
	identityAgentMessagePrefix = "UpdateIdentityAgent"
	identityAgentEntitlements  = "Manage identity agent"
	identityAgentResourceName  = "identityagent"
)

var (
	identityAgentShortDesc = cmdutil.TranslateShortDesc(identityAgentMessagePrefix, "Update an identity agent resource.")

	identityAgentLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identityAgentMessagePrefix, `
        Update an identity agent resource.
       
Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.
 
An empty resource file can be generated using:
 
    verifyctl replace identityagent --boilerplate
 
You can identify the entitlement required by running:
 
  verifyctl replace identityagent --entitlements`))

	identityAgentExamples = templates.Examples(cmdutil.TranslateExamples(identityAgentMessagePrefix, `
        # Generate an empty identityAgent resource template
        verifyctl replace identityagent --boilerplate
       
        # Update a identity agent from a JSON file
        verifyctl replace identityagent -f=./identity_agent.json`))
)

type identityAgentOptions struct {
	options

	config *config.CLIConfig
}

func newIdentityAgentCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identityAgentOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identityAgentUsage,
		Short:                 identityAgentShortDesc,
		Long:                  identityAgentLongDesc,
		Example:               identityAgentExamples,
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

func (o *identityAgentOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, identityAgentResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *identityAgentOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identityAgentOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *identityAgentOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identityAgentEntitlements)
		return nil
	}

	idStr := "<id>"
	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "IdentityAgent",
			APIVersion: "3.0",
			Data: &integrations.IdentityAgentConfig{
				ID: &idStr,
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateIdentityAgent(cmd)
}

func (o *identityAgentOptions) updateIdentityAgent(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)

	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}
	return o.updateIdentityAgentWithData(cmd, b)
}

func (o *identityAgentOptions) updateIdentityAgentWithData(cmd *cobra.Command, data []byte) error {

	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	resourceObj := &resource.ResourceObject{}
	if err := yaml.Unmarshal(data, resourceObj); err != nil {
		vc.Logger.Errorf("unable to unmarshal YAML to resource object; err=%v", err)
		return err
	}
	identityAgent, ok := resourceObj.Data.(*integrations.IdentityAgentConfig)
	if !ok {
		appData, err := yaml.Marshal(resourceObj.Data)
		if err != nil {
			vc.Logger.Errorf("unable to marshal resource data; err=%v", err)
			return err
		}
		identityAgent = &integrations.IdentityAgentConfig{}
		if err := yaml.Unmarshal(appData, identityAgent); err != nil {
			vc.Logger.Errorf("unable to unmarshal data to identity agent; err=%v", err)
			return err
		}
	}
	if err := yaml.Unmarshal(data, &identityAgent); err != nil {
		vc.Logger.Errorf("unable to unmarshal the identityAgent; err=%v", err)
		return err
	}

	client := integrations.NewIdentityAgentClient()
	if err := client.UpdateIdentityAgent(ctx, identityAgent); err != nil {
		vc.Logger.Errorf("unable to update the identity agent; err=%v, identityAgent=%+v", err, identityAgent)
		return err
	}

	cmdutil.WriteString(cmd, "Identity Agent updated successfully")
	return nil
}

func (o *identityAgentOptions) updateIdentityAgentFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	identityAgent := &integrations.IdentityAgentConfig{}
	b, err := yaml.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := yaml.Unmarshal(b, identityAgent); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a identity agent; err=%v", err)
		return err
	}

	client := integrations.NewIdentityAgentClient()
	if err := client.UpdateIdentityAgent(ctx, identityAgent); err != nil {
		vc.Logger.Errorf("unable to update identity agent; err=%v, identityAgent=%+v", err, identityAgent)
		return err
	}

	cmdutil.WriteString(cmd, "Identity Agent updated successfully")
	return nil
}
