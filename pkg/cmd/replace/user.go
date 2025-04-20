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

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
)

const (
	userUsage         = `user [options]`
	userMessagePrefix = "UpdateUser"
	userEntitlements  = "Manage users"
	userResourceName  = "user"
)

var (
	userShortDesc = cmdutil.TranslateShortDesc(userMessagePrefix, "Update a user resource.")

	userLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(userMessagePrefix, `
		Update a user resource.
		
Resources managed on Verify require specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl replace user --boilerplate

You can identify the entitlement required by running:
  
  verifyctl replace user --entitlements`))

	userExamples = templates.Examples(cmdutil.TranslateExamples(userMessagePrefix, `
		# Generate an empty user resource template
		verifyctl replace user --boilerplate
		
		# Update a user from a JSON file
		verifyctl replace user -f=./user-12345.json`))
)

type userOptions struct {
	options

	config *config.CLIConfig
}

func newUserCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &userOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   userUsage,
		Short:                 userShortDesc,
		Long:                  userLongDesc,
		Example:               userExamples,
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

func (o *userOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, userResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. The contents of the file are expected to be formatted to match the API contract."))
}

func (o *userOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *userOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return module.MakeSimpleError(i18n.Translate("'file' option is required if no other options are used."))
	}
	return nil
}

func (o *userOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+userEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "User",
			APIVersion: "2.0",
			Data: &directory.User{
				ID:       "<id>",
				UserName: "<name>",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	return o.updateUser(cmd, auth)
}

func (o *userOptions) updateUser(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// read the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.updateUserWithData(cmd, auth, b)
}

func (o *userOptions) updateUserWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to user object
	user := &directory.UserPatchRequest{}
	if err := json.Unmarshal(data, &user); err != nil {
		vc.Logger.Errorf("unable to unmarshal the user; err=%v", err)
		return err
	}

	client := directory.NewUserClient()
	if err := client.UpdateUser(ctx, auth, user.UserName, user.SCIMPatchRequest.Operations); err != nil {
		vc.Logger.Errorf("unable to update the user; err=%v, user=%+v", err, user)
		return err
	}

	cmdutil.WriteString(cmd, "User updated successfully")
	return nil
}

func (o *userOptions) updateUserFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	// unmarshal to user object
	user := &directory.UserPatchRequest{}
	b, err := json.Marshal(data)

	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, user); err != nil {
		vc.Logger.Errorf("unable to unmarshal to a user; err=%v", err)
		return err
	}

	client := directory.NewUserClient()
	if err := client.UpdateUser(ctx, auth, user.UserName, user.SCIMPatchRequest.Operations); err != nil {
		vc.Logger.Errorf("unable to update the user; err=%v, user=%+v", err, user)
		return err
	}

	cmdutil.WriteString(cmd, "User updated successfully")
	return nil
}
