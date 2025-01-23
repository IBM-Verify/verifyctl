package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	oauth2x "github.com/ibm-security-verify/verifyctl/x/oauth2"
	"github.com/spf13/cobra"
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
	user         bool
	clientID     string
	clientSecret string
	tenant       string
	printOnly    bool
	file         string

	config *config.CLIConfig
}

type AuthResource struct {
	ClientID string `yaml:"client_id" json:"client_id"`

	ClientAuthType string `yaml:"auth_type" json:"auth_type"`

	ClientSecret string `yaml:"client_secret" json:"client_secret"`

	User bool `yaml:"user" json:"user"`

	UserGrantType string `yaml:"grant_type" json:"grant_type"`

	PrivateKeyRaw string `yaml:"key" json:"key"`

	PrivateKeyJWK *jose.JSONWebKey `yaml:"-" json:"-"`
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
	cmd.Flags().BoolVarP(&o.user, "user", "u", o.user, i18n.Translate("Specify if a user login should be initiated."))
	cmd.Flags().StringVar(&o.clientID, "clientId", o.clientID, i18n.Translate("Client ID of the API client or application enabled the appropriate grant type."))
	cmd.Flags().StringVar(&o.clientSecret, "clientSecret", o.clientSecret, i18n.Translate("Client Secret of the API client or application enabled the appropriate grant type. This is optional if the application is configured as a public client."))
	cmd.Flags().StringVarP(&o.file, "file", "f", "", i18n.Translate("Path to the file that contains the input data. JSON and YAML formats are supported and the files are expected to be named with the appropriate extension: json, yml or yaml."))
	cmd.Flags().BoolVar(&o.printOnly, "print", false, i18n.Translate("Specify if the OAuth 2.0 access token should only be displayed and not persisted. Note that this means subsequent commands will not be able to make use of this token."))
}

func (o *options) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return module.MakeSimpleError(i18n.Translate("Tenant is required."))
	}

	o.tenant = args[0]
	o.user = cmd.Flag("user").Changed

	return nil
}

func (o *options) Validate(cmd *cobra.Command, args []string) error {
	if len(o.clientID) == 0 && len(o.file) == 0 {
		return module.MakeSimpleError(i18n.Translate("'clientId' is required."))
	}

	return nil
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	token := ""

	// preferred approach using file
	if o.file != "" {
		authResource, err := o.readFile(cmd)
		if err != nil {
			return err
		}

		var clientAuth oauth2x.ClientAuth
		if authResource.ClientAuthType == "private_key_jwt" {
			clientAuth = &oauth2x.PrivateKeyJWT{
				Tenant:        o.tenant,
				ClientID:      authResource.ClientID,
				PrivateKeyJWK: authResource.PrivateKeyJWK,
			}
		} else {
			clientAuth = &oauth2x.ClientSecretPost{
				ClientID:     authResource.ClientID,
				ClientSecret: authResource.ClientSecret,
			}
		}

		client := &oauth2x.Client{
			Tenant:     o.tenant,
			ClientAuth: clientAuth,
		}

		if authResource.User && authResource.UserGrantType == "auth_code" {

		} else if authResource.User && authResource.UserGrantType == "jwt_bearer" {

		} else if authResource.User {
			deviceAuthResponse, err := client.AuthorizeWithDeviceFlow(cmd.Context(), nil)
			if err != nil {
				return err
			}

			cmdutil.WriteString(cmd, fmt.Sprintf("Complete login by accessing the URL: %s", deviceAuthResponse.VerificationURIComplete))

			tokenResponse, err := client.TokenWithDeviceFlow(ctx, deviceAuthResponse)
			if err != nil {
				return err
			}

			token = tokenResponse.AccessToken
		} else {
			tokenResponse, err := client.TokenWithAPIClient(cmd.Context(), nil)
			if err != nil {
				return err
			}

			token = tokenResponse.AccessToken
		}
	} else {
		// for backward compatibility
		cmdutil.WriteString(cmd, "(deprecated) Use the '-f' argument to provide auth properties")

		client := &oauth2x.Client{
			Tenant: o.tenant,
			ClientAuth: &oauth2x.ClientSecretPost{
				ClientID:     o.clientID,
				ClientSecret: o.clientSecret,
			},
		}

		if o.user {
			deviceAuthResponse, err := client.AuthorizeWithDeviceFlow(cmd.Context(), nil)
			if err != nil {
				return err
			}

			cmdutil.WriteString(cmd, fmt.Sprintf("Complete login by accessing the URL: %s", deviceAuthResponse.VerificationURIComplete))

			tokenResponse, err := client.TokenWithDeviceFlow(ctx, deviceAuthResponse)
			if err != nil {
				return err
			}

			token = tokenResponse.AccessToken
		} else {
			tokenResponse, err := client.TokenWithAPIClient(cmd.Context(), nil)
			if err != nil {
				return err
			}

			token = tokenResponse.AccessToken
		}
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
		Tenant: o.tenant,
		Token:  token,
		User:   o.user,
	})

	// set current tenant
	o.config.SetCurrentTenant(o.tenant)

	// persist contents
	if _, err := o.config.PersistFile(); err != nil {
		return err
	}

	cmdutil.WriteString(cmd, i18n.Translate("Login succeeded."))

	return nil
}

func (o *options) readFile(cmd *cobra.Command) (*AuthResource, error) {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	resourceObject := &resource.ResourceObject{}
	if err := resourceObject.LoadFromFile(cmd, o.file, ""); err != nil {
		vc.Logger.Errorf("unable to read file contents into resource object; err=%v", err)
		return nil, err
	}

	if resourceObject.Kind != resource.ResourceTypePrefix+"Auth" {
		vc.Logger.Error("invalid resource kind", "kind", resourceObject.Kind)
		return nil, fmt.Errorf("invalid resource kind")
	}

	// populate authResource
	b, err := json.Marshal(resourceObject.Data)
	if err != nil {
		return nil, err
	}

	authResource := &AuthResource{}
	if err = json.Unmarshal(b, authResource); err != nil {
		return nil, err
	}

	// if the private key is provided, extract the key
	if authResource.PrivateKeyRaw == "" {
		return authResource, nil
	}

	jwkAsString := authResource.PrivateKeyRaw
	if strings.HasPrefix(authResource.PrivateKeyRaw, "@") {
		// get the contents of the file
		path, _ := strings.CutPrefix(authResource.PrivateKeyRaw, "@")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		jwkAsString = string(b)
	}

	if err := json.Unmarshal([]byte(jwkAsString), authResource.PrivateKeyJWK); err != nil {
		return nil, err
	}

	return authResource, nil
}
