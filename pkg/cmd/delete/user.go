package delete

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usersUsage         = `user [flags]`
	usersMessagePrefix = "DeleteUser"
	usersEntitlements  = "Manage users"
	userResourceName   = "user"
)

var (
	usersLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(usersMessagePrefix, `
		Delete Verify user based on username.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl delete user --entitlements`))

	usersExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Delete an user
		verifyctl delete user --userName=userName`,
	))
)

type usersOptions struct {
	options

	config *config.CLIConfig
}

func NewUserCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &usersOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usersUsage,
		Short:                 cmdutil.TranslateShortDesc(usersMessagePrefix, "Delete Verify user based on an id."),
		Long:                  usersLongDesc,
		Example:               usersExamples,
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

func (o *usersOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd)
	cmd.Flags().StringVar(&o.name, "userName", o.name, i18n.Translate("userName to be deleted"))
}

func (o *usersOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *usersOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		return nil
	}

	calledAs := cmd.CalledAs()
	if calledAs == "user" && o.name == "" {
		return errorsx.G11NError("'userName' flag is required.")
	}
	return nil
}

func (o *usersOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+usersEntitlements)
		return nil
	}

	_, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "user" || len(o.name) > 0 {
		// deal with single user
		return o.handleSingleUser(cmd, args)
	}
	return nil
}

func (o *usersOptions) handleSingleUser(cmd *cobra.Command, _ []string) error {

	c := directory.NewUserClient()
	err := c.DeleteUser(cmd.Context(), o.name)
	if err != nil {
		return err
	}
	cmdutil.WriteString(cmd, "Resource deleted: "+o.name)
	return nil
}
