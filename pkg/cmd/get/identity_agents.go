package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/integrations"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	identityAgentsUsage         = `identityagents [flags]`
	identityAgentsMessagePrefix = "Getidentityagents"
	identityAgentsEntitlements  = "Manage identityagents"
	identityAgentResourceName   = "identityagent"
)

var (
	identityAgentLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identityAgentsMessagePrefix, `
		Get Identity Agents based on an optional filter or a specific identityagent.
		
Resources managed on Verify have specific entitlements, so ensure that the application or Identity agent used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get identityagents --entitlements`))

	identityAgentsExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an identityAgent and print the output in yaml
		verifyctl get identityagent -o=yaml --identityAgentID=testIdentityAgent

		# Get 10 identityAgents based on a given search criteria and sort it in the ascending order by name.
		verifyctl get identityagents --count=2 --sort=identityAgentName -o=yaml`))
)

type identityAgentsOptions struct {
	options
	identityAgentID string
	config          *config.CLIConfig
}

func NewIdentityAgentsCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identityAgentsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identityAgentsUsage,
		Short:                 cmdutil.TranslateShortDesc(identityAgentsMessagePrefix, "Get Identity Agents based on an optional filter or a specific Identity Agent."),
		Long:                  identityAgentLongDesc,
		Example:               identityAgentsExamples,
		Aliases:               []string{"identityagent"},
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

func (o *identityAgentsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, identityAgentResourceName)
	cmd.Flags().StringVar(&o.identityAgentID, "identityAgentID", o.identityAgentID, i18n.Translate("identityAgentID to get details"))
	o.addSortFlags(cmd, identityAgentResourceName)
	o.addCountFlags(cmd, identityAgentResourceName)
}

func (o *identityAgentsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *identityAgentsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "identityagent" && o.identityAgentID == "" {
		return errorsx.G11NError("'identityAgentID' flag is required.")
	}
	return nil
}

func (o *identityAgentsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identityAgentsEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	if cmd.CalledAs() == "identityagent" || len(o.identityAgentID) > 0 {
		return o.handleSingleIdentityAgent(cmd, args)
	}

	return o.handleIdentityAgentList(cmd, args)
}

func (o *identityAgentsOptions) handleSingleIdentityAgent(cmd *cobra.Command, _ []string) error {

	c := integrations.NewIdentityAgentClient()
	identityAgent, uri, err := c.GetIdentityAgentByID(cmd.Context(), o.identityAgentID)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, identityAgent, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "IdentityAgent",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  *identityAgent.ID,
			Name: identityAgent.Name,
			URI:  uri,
		},
		Data: identityAgent,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *identityAgentsOptions) handleIdentityAgentList(cmd *cobra.Command, _ []string) error {

	c := integrations.NewIdentityAgentClient()
	identityAgents, uri, err := c.GetIdentityAgents(cmd.Context(), o.search, o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, identityAgents, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, agent := range *identityAgents {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "IdentityAgent",
			APIVersion: "1.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  *agent.ID,
				Name: agent.Name,
			},
			Data: agent,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "1.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: 10,
		},
		Items: items,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}
