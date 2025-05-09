package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/integrations"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/spf13/cobra"
)

const (
	identityAgentUsage         = "identityagent [options]"
	identityAgentMessagePrefix = "CreateIdentityAgent"
	identityAgentEntitlements  = "Manage Identity Agents"
	identityAgentResourceName  = "identityagent"
)

var (
	identityAgentShortDesc = cmdutil.TranslateShortDesc(identityAgentMessagePrefix, "Options to create an Identity Agent.")

	identityAgentLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identityAgentMessagePrefix, `
        Options to create an Identity Agent.
 
        API clients on Verify require specific entitlements, so ensure that the Identity Agent used
        with the 'auth' command has the required entitlements.
 
        An empty resource file can be generated using:
 
            verifyctl create identityagent --boilerplate
 
        You can check required entitlements by running:
 
            verifyctl create identityagent --entitlements`))

	identityAgentExamples = templates.Examples(cmdutil.TranslateExamples(identityAgentMessagePrefix, `
        # Create an empty Identity agent resource.
        verifyctl create identityagent --boilerplate
 
        # Create an API client using a JSON file.
        verifyctl create identityagent -f=./identityagent.json`))
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the yaml file containing API client data.")
}

func (o *identityAgentOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identityAgentOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return errorsx.G11NError("The 'file' option is required if no other options are used.")
	}
	return nil
}

func (o *identityAgentOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identityAgentEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "IdentityAgent",
			APIVersion: "1.0",
			Data:       &integrations.IdentityAgentConfig{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	_, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.createIdentityAgent(cmd)
}

func (o *identityAgentOptions) createIdentityAgent(cmd *cobra.Command) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createIdentityAgentWithData(cmd, b)
}

func (o *identityAgentOptions) createIdentityAgentWithData(cmd *cobra.Command, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	identityAgentConfig := &integrations.IdentityAgentConfig{}
	if err := json.Unmarshal(data, &identityAgentConfig); err != nil {
		vc.Logger.Errorf("unable to unmarshal API client; err=%v", err)
		return err
	}

	client := integrations.NewIdentityAgents()
	resourceURI, err := client.CreateIdentityAgent(ctx, identityAgentConfig)
	if err != nil {
		vc.Logger.Errorf("failed to create API client; err=%v", err)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *identityAgentOptions) createIdentityAgentFromDataMap(cmd *cobra.Command, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// Convert map data to JSON
	identityAgentConfig := &integrations.IdentityAgentConfig{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal data; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, identityAgentConfig); err != nil {
		vc.Logger.Errorf("unable to unmarshal data to Identoty Agent; err=%v", err)
		return err
	}

	// Create API client
	client := integrations.NewIdentityAgents()
	resourceURI, err := client.CreateIdentityAgent(ctx, identityAgentConfig)
	if err != nil {
		vc.Logger.Errorf("failed to create API client; err=%v", err)
		return err
	}

	// Directly return the created resource URI
	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
