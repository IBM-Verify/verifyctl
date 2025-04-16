package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"

	"github.com/ibm-verify/verifyctl/pkg/module"
	"github.com/ibm-verify/verifyctl/pkg/module/directory"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	groupUsage         = "group [options]"
	groupMessagePrefix = "CreateGroup"
	groupEntitlements  = "Manage groups"
	groupResourceName  = "group"
)

var (
	groupShortDesc = cmdutil.TranslateShortDesc(groupMessagePrefix, "Additional options to create a group.")

	groupLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(groupMessagePrefix, `
		Additional options to create a group.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create group --boilerplate

You can identify the entitlement required by running:

	verifyctl create group --entitlements`))

	groupExamples = templates.Examples(cmdutil.TranslateExamples(groupMessagePrefix, `
		# Create an empty group resource. This can be piped into a file.
		verifyctl create group --boilerplate

		# Create a group using a JSON file.
		verifyctl create group -f=./group.json`))
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the JSON file containing group data.")
}

func (o *groupOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *groupOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return module.MakeSimpleError("The 'file' option is required if no other options are used.")
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
			APIVersion: "2.0",
			Data:       &directory.Group{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.createGroup(cmd, auth)
}

func (o *groupOptions) createGroup(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	// create group with data
	return o.createGroupWithData(cmd, auth, b)
}

func (o *groupOptions) createGroupWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to group
	group := &directory.Group{}
	if err := json.Unmarshal(data, &group); err != nil {
		vc.Logger.Errorf("unable to unmarshal the group; err=%v", err)
		return err
	}

	client := directory.NewGroupClient()
	resourceURI, err := client.CreateGroup(ctx, auth, group)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *groupOptions) createGroupFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to group
	group := &directory.Group{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, group); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an group; err=%v", err)
		return err
	}

	client := directory.NewGroupClient()
	resourceURI, err := client.CreateGroup(ctx, auth, group)
	if err != nil {
		vc.Logger.Errorf("unable to create the group; err=%v, group=%+v", err, group)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
