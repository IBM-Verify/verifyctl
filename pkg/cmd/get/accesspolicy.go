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
	accessPoliciesUsage         = `accesspolicies [flags]`
	accessPoliciesMessagePrefix = "GetAccesspolicies"
	accessPoliciesEntitlements  = "Manage accessPolicies"
	accessPolicyResourceName    = "accesspolicy"
)

var (
	accessPoliciesLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(accessPoliciesMessagePrefix, `
		Get Verify accessPolicies based on an optional filter or a specific accessPolicy.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get accesspolicies --entitlements`))

	accessPoliciesExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an accessPolicy and print the output in yaml
		verifyctl get accesspolicy -o=yaml --ID=testAccesspolicyID

		# Get 2 accessPolicies .
		verifyctl get accesspolicies --limit=2 --page=1 -o=yaml`))
)

type accessPoliciesOptions struct {
	options
	accessPolicyID string
	config         *config.CLIConfig
}

func NewAccesspoliciesCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &accessPoliciesOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   accessPoliciesUsage,
		Short:                 cmdutil.TranslateShortDesc(accessPoliciesMessagePrefix, "Get Verify accessPolicies based on an optional filter or a specific accessPolicy."),
		Long:                  accessPoliciesLongDesc,
		Example:               accessPoliciesExamples,
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

func (o *accessPoliciesOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, accessPolicyResourceName)
	cmd.Flags().StringVar(&o.accessPolicyID, "accessPolicyID", o.accessPolicyID, i18n.Translate("accessPolicyID to get details"))
	o.addSortFlags(cmd, accessPolicyResourceName)
	o.addPaginationFlags(cmd, accessPolicyResourceName)
}

func (o *accessPoliciesOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *accessPoliciesOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "accesspolicy" && o.accessPolicyID == "" {
		return errorsx.G11NError("'accessPolicyID' flag is required.")
	}
	return nil
}

func (o *accessPoliciesOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+accessPoliciesEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "accesspolicy" || len(o.accessPolicyID) > 0 {
		return o.handleSingleAccesspolicy(cmd, args)
	}

	return o.handleAccesspolicyList(cmd, args)
}

func (o *accessPoliciesOptions) handleSingleAccesspolicy(cmd *cobra.Command, _ []string) error {

	c := security.NewAccessPolicyClient()
	ap, uri, err := c.GetAccessPolicy(cmd.Context(), o.accessPolicyID)
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

func (o *accessPoliciesOptions) handleAccesspolicyList(cmd *cobra.Command, _ []string) error {

	c := security.NewAccessPolicyClient()
	accessPolicies, uri, err := c.GetAccessPolicies(cmd.Context(), o.page, o.limit)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, accessPolicies, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, ap := range accessPolicies.Policies {
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
			Total: len(items),
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
