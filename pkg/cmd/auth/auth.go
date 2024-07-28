package auth

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/vivshankar/verifyctl/pkg/config"
	"github.com/vivshankar/verifyctl/pkg/i18n"
	cmdutil "github.com/vivshankar/verifyctl/pkg/util/cmd"
	"github.com/vivshankar/verifyctl/pkg/util/templates"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	usage         = "auth [hostname] [flags]"
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
		
In both cases, an OAuth token is generated with specific entitlements.`))

	examples = templates.Examples(cmdutil.TranslateExamples(messagePrefix, `
		# Login interactively as a user. This uses a valid OAuth client registered on the tenant
		# that is enabled with device flow grant type.
		#
		# The connection created is permitted to perform actions based on the entitlements that
		# are configured on the OAuth client and the entitlements of the user based on assigned groups and roles.
		verifyctl auth abc.verify.ibm.com -u --clientId=cli_user_client --clientSecret=cli_user_secret

		# Authenticate an API client to get an authorized token.
		#
		# The connection created is permitted to perform actions based on the entitlements that
		# are configured on the API client.
		verifyctl auth abc.verify.ibm.com --clientId=cli_api_client --clientSecret=cli_api_secret`))
)

type options struct {
	User           bool
	ClientID       string
	ClientSecret   string
	TenantHostname string

	config *config.CLIConfig
}

func NewCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &options{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   usage,
		Short:                 cmdutil.TranslateShortDesc(messagePrefix, "Log in to your tenant and save the connection for subsequent use."),
		Long:                  longDesc,
		Example:               examples,
		DisableFlagsInUseLine: true,
		Aliases:               []string{"auth", "login"},
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

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&o.User, "user", "u", o.User, i18n.Translate("Specify if a user login should be initiated."))
	cmd.Flags().StringVar(&o.ClientID, "clientId", o.ClientID, i18n.Translate("Client ID of the application that is enabled for device flow grant type."))
	cmd.Flags().StringVar(&o.ClientSecret, "clientSecret", o.ClientSecret, i18n.Translate("Client Secret of the application that is enabled for device flow grant type. This is optional if the application is configured as a public client."))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf(i18n.Translate("Tenant is required."))
	}

	o.TenantHostname = args[0]
	o.User = cmd.Flag("user").Changed

	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	if len(o.ClientID) == 0 {
		return fmt.Errorf(i18n.Translate("'clientId' is required."))
	}

	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	token := ""
	if o.User {
		oauthConfig := &oauth2.Config{
			ClientID:     o.ClientID,
			ClientSecret: o.ClientSecret,
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: fmt.Sprintf("https://%s/oauth2/device_authorization", o.TenantHostname),
				TokenURL:      fmt.Sprintf("https://%s/oauth2/token", o.TenantHostname),
			},
		}

		deviceAuthResponse, err := oauthConfig.DeviceAuth(ctx)
		if err != nil {
			return err
		}

		cmdutil.WriteString(cmd, fmt.Sprintf("Complete login by accessing the URL: %s", deviceAuthResponse.VerificationURIComplete))

		tokenResponse, err := oauthConfig.DeviceAccessToken(ctx, deviceAuthResponse)
		if err != nil {
			return err
		}

		token = tokenResponse.AccessToken
	} else {
		oauthConfig := &clientcredentials.Config{
			ClientID:     o.ClientID,
			ClientSecret: o.ClientSecret,
			TokenURL:     fmt.Sprintf("https://%s/oauth2/token", o.TenantHostname),
		}

		tokenResponse, err := oauthConfig.Token(ctx)
		if err != nil {
			return err
		}

		token = tokenResponse.AccessToken
	}

	// add token to config
	if _, err := o.config.LoadFromFile(); err != nil {
		return err
	}

	o.config.AddAuth(&config.AuthConfig{
		Tenant: o.TenantHostname,
		Token:  token,
		User:   o.User,
	})

	// set current tenant
	o.config.SetCurrentTenant(o.TenantHostname)

	// persist contents
	if _, err := o.config.PersistFile(); err != nil {
		return err
	}

	return nil
}
