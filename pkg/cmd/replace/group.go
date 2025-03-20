package replace

import (
	"encoding/json"
	"io"
	"os"

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
	groupUsage         = `group [options]`
	groupMessagePrefix = "UpdateGroup"
	groupEntitlements  = "Manage groups"
	groupResourceName  = "group"
)

var (
	groupShortDesc = cmdutil.TranslateShortDesc(groupMessagePrefix, "Update a group resource.")

	groupLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(groupMessagePrefix, `
		Update a group resource.

Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl replace group --boilerplate

You can identify the entitlement required by running:

  verifyctl replace group --entitlements`))

	groupExamples = templates.Examples(cmdutil.TranslateExamples(groupMessagePrefix, `
		# Generate an empty group resource template
		verifyctl replace group --boilerplate

		# Update a group from a JSON file
		verifyctl replace group -f=./group-12345.json`))
)

type groupOptions struct {
	options

	config *config.CLIConfig
}

func newGroupCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &groupOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   groupUsage,
		Short:                 groupShortDesc,
		Long:                  groupLongDesc,
		Example:               groupExamples,
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

func (o *groupOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, groupResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *groupOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *groupOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return module.MakeSimpleError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *groupOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+groupEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Group",
			APIVersion: "1.0",
			Data: &directory.Group{
				Id:          "<id>",
				DisplayName: "<name>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.updateGroup(cmd, auth)
}

func (o *groupOptions) updateGroup(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateGroupWithData(cmd, auth, b)
}

func (o *groupOptions) updateGroupWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to group object
	group := &directory.GroupPatchRequest{}
	if err := json.Unmarshal(data, &group); err != nil {
		vc.Logger.Errorf("unable to unmarshal the group; err=%v", err)
		return err
	}

	client := directory.NewGroupClient()
	if err := client.UpdateGroup(ctx, auth, group.GroupName, group.SCIMPatchRequest.Operations); err != nil {
		vc.Logger.Errorf("unable to update the group; err=%v, group=%+v", err, group)
		return err
	}

	cmdutil.WriteString(cmd, "Group updated successfully")
	return nil
}

func (o *groupOptions) updateGroupFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to group object
	group := &directory.GroupPatchRequest{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, group); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a group; err=%v", err)
		return err
	}

	client := directory.NewGroupClient()
	if err := client.UpdateGroup(ctx, auth, group.GroupName, group.SCIMPatchRequest.Operations); err != nil {
		vc.Logger.Errorf("unable to update the group; err=%v, group=%+v", err, group)
		return err
	}

	cmdutil.WriteString(cmd, "Group updated successfully")
	return nil
}
