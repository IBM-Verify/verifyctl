package login

import (
	"context"
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
	usage = "login [hostname] [flags]"
)

var (
	longDesc = templates.LongDesc(i18n.TranslateWithCode(i18n.LoginLongDesc, `
		Log in to your tenant and save the connection for subsequent use until the security token expires.
		
		First-time users of the client should run this command to connect to a tenant, establish an authenticated session, and
save the connection details to the configuration file. The configuration will be saved to your home directory under
".verify/config".

		There are two methods to login - as a user providing credentials and as an API client. This information is provided through flags.`))

	examples = templates.Examples(i18n.TranslateWithCode(i18n.LoginExamples, `
		# Login interactively as a user. This uses a valid OAuth client registered on the tenant
		# that is enabled with device flow grant type.
		#
		# The connection created is permitted to perform actions based on the entitlements that
		# are configured on the OAuth client and the entitlements of the user based on assigned groups and roles.
		verifyctl login abc.verify.ibm.com -u --clientId=cli_user_client --clientSecret=cli_user_secret

		# Login using an API client.
		#
		# The connection created is permitted to perform actions based on the entitlements that
		# are configured on the API client.
		verifyctl login abc.verify.ibm.com --clientId=cli_api_client --clientSecret=cli_api_secret`))
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
		Short:                 i18n.TranslateWithCode(i18n.LoginShortDesc, "Log in to your tenant and save the connection for subsequent use."),
		Long:                  longDesc,
		Example:               examples,
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
	ctx := context.Background()

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

		_, _ = io.WriteString(cmd.OutOrStdout(), fmt.Sprintf("Complete login by accessing the URL: %s\n", deviceAuthResponse.VerificationURIComplete))

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

	// persist contents
	if _, err := o.config.PersistFile(); err != nil {
		return err
	}

	return nil
}
