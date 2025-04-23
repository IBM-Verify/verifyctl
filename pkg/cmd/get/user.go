package get

import (
	"io"

	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usersUsage         = `users [flags]`
	usersMessagePrefix = "GetUsers"
	usersEntitlements  = "Manage users"
	userResourceName   = "user"
)

var (
	usersLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(usersMessagePrefix, `
		Get Verify users based on an optional filter or a specific user.
		
Resources managed on Verify have specific entitlements, so ensure that the application or API client used
with the 'auth' command is configured with the appropriate entitlements.

You can identify the entitlement required by running:
  
  verifyctl get users --entitlements`))

	usersExamples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Get an user and print the output in yaml
		verifyctl get user -o=yaml --userName=testUser

		# Get 10 users based on a given search criteria and sort it in the ascending order by name.
		verifyctl get users --count=2 --sort=userName -o=yaml`))
)

type usersOptions struct {
	options

	config *config.CLIConfig
}

func NewUsersCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &usersOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usersUsage,
		Short:                 cmdutil.TranslateShortDesc(usersMessagePrefix, "Get Verify users based on an optional filter or a specific user."),
		Long:                  usersLongDesc,
		Example:               usersExamples,
		Aliases:               []string{"user"},
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
	o.addCommonFlags(cmd, userResourceName)
	cmd.Flags().StringVar(&o.name, "userName", o.name, i18n.Translate("userName to get details"))
	o.addSortFlags(cmd, userResourceName)
	o.addCountFlags(cmd, userResourceName)
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

	auth, err := o.config.SetAuthToContext(cmd.Context())
	if err != nil {
		return err
	}

	// invoke the operation
	if cmd.CalledAs() == "user" || len(o.name) > 0 {
		// deal with single user
		return o.handleSingleUser(cmd, auth, args)
	}

	return o.handleUserList(cmd, auth, args)
}

func (o *usersOptions) handleSingleUser(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewUserClient()
	usr, uri, err := c.GetUser(cmd.Context(), o.name)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, usr, cmd.OutOrStdout())
		return nil
	}

	resourceObj := &resource.ResourceObject{
		Kind:       resource.ResourceTypePrefix + "User",
		APIVersion: "2.0",
		Metadata: &resource.ResourceObjectMetadata{
			UID:  usr.ID,
			Name: usr.UserName,
			URI:  uri,
		},
		Data: usr,
	}

	if o.output == "json" {
		cmdutil.WriteAsJSON(cmd, resourceObj, cmd.OutOrStdout())
	} else {
		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
	}

	return nil
}

func (o *usersOptions) handleUserList(cmd *cobra.Command, auth *config.AuthConfig, _ []string) error {

	c := directory.NewUserClient()
	usrs, uri, err := c.GetUsers(cmd.Context(), o.sort, o.count)
	if err != nil {
		return err
	}

	if o.output == "raw" {
		cmdutil.WriteAsJSON(cmd, usrs, cmd.OutOrStdout())
		return nil
	}

	items := []*resource.ResourceObject{}
	for _, usr := range *usrs.Resources {
		items = append(items, &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "User",
			APIVersion: "2.0",
			Metadata: &resource.ResourceObjectMetadata{
				UID:  usr.ID,
				Name: usr.UserName,
			},
			Data: usr,
		})
	}

	resourceObj := &resource.ResourceObjectList{
		Kind:       resource.ResourceTypePrefix + "List",
		APIVersion: "2.0",
		Metadata: &resource.ResourceObjectMetadata{
			URI:   uri,
			Total: int(usrs.TotalResults),
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
