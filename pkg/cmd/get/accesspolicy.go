package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	accesspoliciesUsage         = `accesspolicies [flags]`
	accesspoliciesMessagePrefix = "GetAccesspolicies"
	accesspoliciesEntitlements  = "Manage accesspolicies"
	accesspolicyResourceName    = "accesspolicy"
)

var (
	accesspoliciesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accesspoliciesMessagePrefix, `
		Get Verify accesspolicies based on an optional filter or a specific accesspolicy.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get accesspolicies --entitlements`))

	accesspoliciesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an accesspolicy and print the output in yaml
		verifyctl get accesspolicy -o=yaml --name=testAccesspolicy

		# Get 10 accesspolicies based on a given search criteria and sort it in the ascending order by name.
		verifyctl get accesspolicies --count=2 --sort=accesspolicyName -o=yaml`))
)

type accesspoliciesOptions struct {
	options

	config *config.CLIConfig
}

func NewAccesspoliciesCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &accesspoliciesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   accesspoliciesUsage,
		Short:                 cmdutil.TranslateShortDesc(accesspoliciesMessagePrefix, "Get Verify accesspolicies based on an optional filter or a specific accesspolicy."),
		Long:                  accesspoliciesLongDesc,
		Example:               accesspoliciesExamples,
		Aliases:               []string{"accesspolicy"},
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

func (o *accesspoliciesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, accesspolicyResourceName)
	cmd.Flags().StringVar(&o.name, "accesspolicyName", o.name, i18n.Translate("accesspolicyName to get details"))

}

func (o *accesspoliciesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accesspoliciesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "accesspolicy" && o.name == "" {
		return errorsx.G11NError("'accesspolicyName' flag is required.")
	}
	return nil
}

func (o *accesspoliciesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+accesspoliciesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "accesspolicy" || len(o.name) > 0 {
		// deal with single accesspolicy
		return o.handleSingleAccesspolicy(cmd, args)
	}

	return o.handleAccesspolicyList(cmd, args)
}

func (o *accesspoliciesOptions) handleSingleAccesspolicy(cmd *cobra.Command, _ []string) error {

	c := security.NewAccesspolicyClient()
	ap, uri, err := c.GetAccesspolicy(cmd.Context(), o.name)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, ap, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "AccessPolicy",
		APIVersion: "5.0",
		Metadata: &resource.ResourceObjectMetadata{
			ID:   ap.ID,
			Name: ap.Name,
			URI:  uri,
		},
		Data: ap,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *accesspoliciesOptions) handleAccesspolicyList(cmd *cobra.Command, _ []string) error {

	c := security.NewAccesspolicyClient()
	accesspolicies, uri, err := c.GetAccesspolicies(cmd.Context())
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, accesspolicies, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, ap := range *accesspolicies.Policies {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "AccessPolicy",
			APIVersion: "5.0",
			Metadata: &resource.ResourceObjectMetadata{
				ID:   ap.ID,
				Name: ap.Name,
			},
			Data: ap,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "5.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: int(accesspolicies.Total),
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
