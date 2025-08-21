package auth

import (
	"io"
	"net/url"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-verify/verifyctl/pkg/util/templates"
	"github.com/spf13/cobra"
)

const (
	usage         = "auth [flags]"
	messagePrefix = "Auth"
)

var (
	longDesc = templates.LongDesc(cmdutil.TranslateLongDesc(messagePrefix, `
		Log in to your tenant and save the connection for subsequent use until the security token expires.
		
First-time users of the client should run this command to connect to a tenant to establish an authorized session. 
The issued OAuth 2.0 security token is saved to the configuration file at your home directory under ".verify/config".

There are two methods to generate the authorized token, based on flags:
		
  - As a user providing credentials
  - As an API client
		
In both cases, an OAuth token is generated with specific entitlements.

The auth resource file can be generated using:

  verifyctl auth --boilerplate`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Login interactively as a user or an API client. For user login, the application on Verify
		# should be configured with the OAuth 2.0 Device Flow.
		#
		# The connection created is permitted to perform actions based on the entitlements that
		# are configured on the OAuth client and the entitlements of the user based on assigned groups and roles.
		verifyctl auth -f "login.yaml"
	`))
)

type options struct {
	boilerplate  bool
	user         bool
	clientID     string
	clientSecret string
	tenant       string
	printOnly    bool
	file         string

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter, groupID string) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 cmdutil.TranslateShortDesc(messagePrefix, "Log in to your tenant and save the connection for subsequent use."),
		Long:                  longDesc,
		Example:               examples,
		DisableFlagsInUseLine: true,
		Aliases:               []string{"login"},
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
		GroupID: groupID,
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)

	return cmd
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.boilerplate, "boilerplate", o.boilerplate, i18n.TranslateWithArgs("Generate an empty %s file. This will be in YAML format.", "auth"))
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file parameters used to authenticate the request. JSON and YAML formats are supported and the files are expected to be named with the appropriate extension: json, yml or yaml."))
	cmd.Flags().BoolVar(&o.printOnly, "print", false, i18n.Translate("Specify if the OAuth 2.0 access token should only be displayed and not persisted. Note that this means subsequent commands will not be able to make use of this token."))
	cmd.Flags().BoolVarP(&o.user, "user", "u", o.user, i18n.Translate("(Deprecated) Specify if a user login should be initiated."))
	cmd.Flags().StringVar(&o.clientID, "clientId", o.clientID, i18n.Translate("(Deprecated) Client ID of the API client or application enabled the appropriate grant type."))
	cmd.Flags().StringVar(&o.clientSecret, "clientSecret", o.clientSecret, i18n.Translate("(Deprecated) Client Secret of the API client or application enabled the appropriate grant type. This is optional if the application is configured as a public client."))

}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	o.user = cmd.Flag("user").Changed
	if len(args) == 0 {
		return nil
	}

	o.tenant = args[0]
	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	if o.boilerplate {
		return nil
	}

	if len(o.clientID) == 0 && len(o.file) == 0 {
		return errorsx.G11NError("'clientId' is required.")
	}

	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "Auth",
			APIVersion: "1.0",
			Data: &AuthResource{
				Tenant: "abc.verify.ibm.com",
				Parameters: url.Values{
					"foo": []string{"bar"},
				},
				ClientAuthType: "private_key_jwt",
				PrivateKeyRaw:  "<serialized_jwk> when auth_type is private_key_jwt",
			},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	token := ""
	var authResource *AuthResource
	var err error

	// preferred approach using file
	if o.file != "" {
		authResource, err = o.readFile(cmd)
		if err != nil {
			return err
		}

		if len(authResource.Tenant) == 0 {
			authResource.Tenant = o.tenant
		}
	} else {
		// for backward compatibility
		cmdutil.WriteString(cmd, "(deprecated) Use the '-f' argument to provide auth properties")
		authResource = &AuthResource{
			Tenant:       o.tenant,
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
			User:         o.user,
		}
	}

	if len(authResource.Tenant) == 0 {
		return errorsx.G11NError("'tenant' is required.")
	}

	if tokenResponse, err := o.authenticate(cmd, authResource); err != nil {
		vc.Logger.Warn("authentication failed", "client", authResource.ClientID, "err", err)
		return err
	} else {
		token = tokenResponse.AccessToken
	}

	if o.printOnly {
		cmdutil.WriteString(cmd, token)
		return nil
	}

	// add token to config
	if _, err := o.config.LoadFromFile(); err != nil {
		return err
	}

	o.config.AddAuth(&config.AuthConfig{
		Tenant: authResource.Tenant,
		Token:  token,
		User:   authResource.User,
	})

	// set current tenant
	o.config.SetCurrentTenant(authResource.Tenant)

	// persist contents
	if _, err := o.config.PersistFile(); err != nil {
		return err
	}

	cmdutil.WriteString(cmd, i18n.Translate("Login succeeded."))
	return nil
}
