package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/integrations"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	identityAgentUsage         = `identityagent [flags]`
	identityAgentMessagePrefix = "DeleteIdentityAgent"
	identityAgentEntitlements  = "Manage identityAgents"
	identityAgentResourceName  = "identityagent"
)

var (
	identityAgentLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(identityAgentMessagePrefix, `
		Delete Identity Agent based on identityAgentID.
		
Resources managed on Verify have specific entitlements, so ensure that the Identity agents used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete identityagent --entitlements`))

	identityAgentExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an Identity Agent by ID
		verifyctl delete identityagent --identityAgentID="12345"`,
	))
)

type identityAgentsOptions struct {
	options
	identityAgentID string
	config          *config.CLIConfig
}

func NewIdentityAgentCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &identityAgentsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   identityAgentUsage,
		Short:                 cmdutil.TranslateShortDesc(identityAgentMessagePrefix, "Delete Identity Agent based on its id."),
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

func (o *identityAgentsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.identityAgentID, "identityAgentID", o.identityAgentID, i18n.Translate("identityAgentID to be deleted"))
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
		return errorsx.G11NError("'identityAgentID' flag is required")
	}
	return nil
}

func (o *identityAgentsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+identityAgentEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "identityagent" {
		// deal with single Identity Agent
		return o.handleSingleIdentityAgent(cmd, args)
	}
	return nil
}

func (o *identityAgentsOptions) handleSingleIdentityAgent(cmd *cobra.Command, _ []string) error {
	c := integrations.NewIdentityAgents()
	var id string
	var err error

	if o.identityAgentID != "" {
		id = o.identityAgentID
		err = c.DeleteIdentityAgentsById(cmd.Context(), id)
		if err != nil {
			return err
		}
	} else {
		return errorsx.G11NError("either clientName or clientId must be provided")
	}

	resourceIdentifier := o.identityAgentID
	cmdutil.WriteString(cmd, "Resource deleted with ID: "+resourceIdentifier)
	return nil
}
