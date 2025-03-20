package get

import (
	"io"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/directory"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	groupsUsage         = `groups [flags]`
	groupsMessagePrefix = "GetGroups"
	groupsEntitlements  = "Manage groups"
	groupResourceName   = "group"
)

var (
	groupsLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(groupsMessagePrefix, `
		Get Verify groups based on an optional filter or a specific group.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get groups --entitlements`))

	groupsExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an group and print the output in yaml
		verifyctl get group -o=yaml --displayName=admin

		# Get 10 groups based on a given search criteria and sort it in the ascending order by name.
		verifyctl get groups --count=2 --sort=groupName -o=yaml`))
)

type groupsOptions struct {
	options

	config *config.CLIConfig
}

func NewGroupsCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &groupsOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   groupsUsage,
		Short:                 cmdutil.TranslateShortDesc(groupsMessagePrefix, "Get Verify groups based on an optional filter or a specific group."),
		Long:                  groupsLongDesc,
		Example:               groupsExamples,
		Aliases:               []string{"group"},
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

func (o *groupsOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, groupResourceName)
	cmd.Flags().StringVar(&o.name, "displayName", o.name, i18n.Translate("Group displayName to get details"))
	o.addSortFlags(cmd, groupResourceName)
	o.addCountFlags(cmd, groupResourceName)
}

func (o *groupsOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *groupsOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "group" && o.name == "" {
		return module.MakeSimpleError(i18n.Translate("'displayName' flag is required."))
	}
	return nil
}

func (o *groupsOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+groupsEntitlements)
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "group" || len(o.name) > 0 {
		// deal with single group
		return o.handleSingleGroup(cmd, auth, args)
	}

	return o.handleGroupList(cmd, auth, args)
}

func (o *groupsOptions) handleSingleGroup(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewGroupClient()
	grp, uri, err := c.GetGroup(cmd.Context(), auth, o.name)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, grp, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "Group",
		APIVersion: "2.0",
		Metadata: &resource.ResourceObjectMetadata{
			Name: grp.DisplayName,
			URI:  uri,
		},
		Data: grp,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *groupsOptions) handleGroupList(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewGroupClient()
	grps, uri, err := c.GetGroups(cmd.Context(), auth, o.sort, o.count)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, grps, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, grp := range grps.Groups {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Group",
			APIVersion: "2.0",
			Metadata: &resource.ResourceObjectMetadata{
				Name: grp.DisplayName,
			},
			Data: grp,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "2.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: grps.TotalResults,
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
