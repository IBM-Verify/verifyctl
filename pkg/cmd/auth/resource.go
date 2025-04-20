package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/ibm-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-verify/verifyctl/pkg/i18n"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"github.com/spf13/cobra"

	oidc "github.com/ibm-verify/verify-sdk-go/pkg/auth"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
)

type AuthResource struct {
	Tenant string `yaml:"tenant" json:"tenant"`

	ClientID string `yaml:"client_id" json:"client_id"`

	ClientAuthType string `yaml:"auth_type" json:"auth_type"`

	ClientSecret string `yaml:"client_secret" json:"client_secret"`

	Scopes []string `yaml:"scopes" json:"scopes"`

	Parameters url.Values `yaml:"params" json:"params"`

	User bool `yaml:"user" json:"user"`

	PrivateKeyRaw string `yaml:"key" json:"key"`

	PrivateKeyJWK *jose.JSONWebKey `yaml:"-" json:"-"`
}

func (r *AuthResource) ConvertToClient() *oidc.Client {
	client := &oidc.Client{
		Tenant: r.Tenant,
		Scopes: r.Scopes,
	}

	if r.ClientAuthType == "private_key_jwt" {
		client.ClientAuth = &oidc.PrivateKeyJWT{
			Tenant:        r.Tenant,
			ClientID:      r.ClientID,
			PrivateKeyJWK: r.PrivateKeyJWK,
		}
	} else {
		client.ClientAuth = &oidc.ClientSecretPost{
			ClientID:     r.ClientID,
			ClientSecret: r.ClientSecret,
		}
	}

	return client
}

func (o *options) authenticate(cmd *cobra.Command, r *AuthResource) (*oidc.TokenResponse, error) {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)
	client := r.ConvertToClient()

	if r.User {
		deviceAuthResponse, err := client.AuthorizeWithDeviceFlow(ctx, r.Parameters)
		if err != nil {
			vc.Logger.Errorf("Failed to initiate device flow: err=%v", err)
			return nil, err
		}

		cmdutil.WriteString(cmd, i18n.TranslateWithArgs("Login with %s", deviceAuthResponse.VerificationURIComplete))

		tokenResponse, err := client.TokenWithDeviceFlow(ctx, deviceAuthResponse)
		if err != nil {
			vc.Logger.Errorf("Unable to get a token: err=%v", err)
			return nil, err
		}

		return tokenResponse, nil
	}

	tokenResponse, err := client.TokenWithAPIClient(cmd.Context(), r.Parameters)
	if err != nil {
		vc.Logger.Errorf("Unable to get a token: err=%v", err)
		return nil, err
	}

	return tokenResponse, nil
}

func (o *options) readFile(cmd *cobra.Command) (*AuthResource, error) {
	ctx := cmd.Context()
	vc := contextx.GetVerifyContext(ctx)

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

	authResource.PrivateKeyJWK = &jose.JSONWebKey{}
	if err := json.Unmarshal([]byte(jwkAsString), authResource.PrivateKeyJWK); err != nil {
		return nil, err
	}

	return authResource, nil
}
