package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
	"github.com/spf13/cobra"
)

type AuthResource struct {
	ClientID string `yaml:"client_id" json:"client_id"`

	ClientAuthType string `yaml:"auth_type" json:"auth_type"`

	ClientSecret string `yaml:"client_secret" json:"client_secret"`

	User bool `yaml:"user" json:"user"`

	UserGrantType string `yaml:"grant_type" json:"grant_type"`

	PrivateKeyRaw string `yaml:"key" json:"key"`

	PrivateKeyJWK *jose.JSONWebKey `yaml:"-" json:"-"`
}

func (o *options) authenticate(cmd *cobra.Command, r *AuthResource) (*openapi.TokenResponse, error) {
	var tokenResponse openapi.TokenResponse
	if r.User && r.UserGrantType == "auth_code" {
		return nil, fmt.Errorf("not implemented")
	} else if r.User && r.UserGrantType == "jwt_bearer" {
		return nil, fmt.Errorf("not implemented")
	} else if r.User {
		return nil, fmt.Errorf("not implemented")
	} else {
		formData := url.Values{}
		formData.Add("client_id", r.ClientID)
		formData.Add("client_secret", r.ClientSecret)
		formData.Add("grant_type", "client_credentials")
		client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", o.tenant))
		resp, err := client.PostOauth2TokenWithBodyWithResponse(cmd.Context(), nil, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
		if err != nil {
			fmt.Println(err)
		} else {
			err = json.Unmarshal(resp.Body, &tokenResponse)
			if err != nil {
				return nil, err
			}
		}
	}

	return &tokenResponse, nil
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

	authResource.PrivateKeyJWK = &jose.JSONWebKey{}
	if err := json.Unmarshal([]byte(jwkAsString), authResource.PrivateKeyJWK); err != nil {
		return nil, err
	}

	return authResource, nil
}
