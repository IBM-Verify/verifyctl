package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"

	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/directory"
	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	userUsage         = "user [options]"
	userMessagePrefix = "CreateUser"
	userEntitlements  = "Manage users"
	userResourceName  = "user"
)

var (
	userShortDesc = cmdutil.TranslateShortDesc(userMessagePrefix, "Additional options to create a user.")

	userLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(userMessagePrefix, `
		Additional options to create a user.

Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

An empty resource file can be generated using:

	verifyctl create user --boilerplate

You can identify the entitlement required by running:

	verifyctl create user --entitlements`))

	userExamples = templates.Examples(cmdutil.TranslateExamples(userMessagePrefix, `
		# Create an empty user resource. This can be piped into a file.
		verifyctl create user --boilerplate

		# Create a user using a JSON file.
		verifyctl create user -f=./user.json`))
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
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the JSON file containing user data.")
}

func (o *userOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *userOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return module.MakeSimpleError("The 'file' option is required if no other options are used.")
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
			Data:       &directory.User{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.createUser(cmd, auth)
}

func (o *userOptions) createUser(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// get the contents of the file
	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	// create user with data
	return o.createUserWithData(cmd, auth, b)
}

func (o *userOptions) createUserWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to user
	user := &openapi.UserV2{}
	if err := json.Unmarshal(data, &user); err != nil {
		vc.Logger.Errorf("unable to unmarshal the user; err=%v", err)
		return err
	}

	client := directory.NewUserClient()
	resourceURI, err := client.CreateUser(ctx, auth, user)
	if err != nil {
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *userOptions) createUserFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// unmarshal to user
	user := &openapi.UserV2{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal the data map; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, user); err != nil {
		vc.Logger.Errorf("unable to unmarshal to an user; err=%v", err)
		return err
	}

	client := directory.NewUserClient()
	resourceURI, err := client.CreateUser(ctx, auth, user)
	if err != nil {
		vc.Logger.Errorf("unable to create the user; err=%v, user=%+v", err, user)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
