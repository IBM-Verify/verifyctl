package oauth

import (
	"context"
	"fmt"
	"net/url"

	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
	"golang.org/x/oauth2/clientcredentials"
)

type ClientAuth interface {
	GetMethod() string

	GetParameters() url.Values
}

type ClientSecretPost struct {
	ClientID string

	ClientSecret string

	Public bool
}

type PrivateKeyJWT struct {
}

type Config struct {
	ClientID string `json:"client_id" yaml:"client_id"`

	ClientSecret string `json:"`
}

type Client struct {
	client xhttp.Clientx
}

func NewClient() *Client {
	return &Client{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *Client) GetTokenWithClientCredentials(ctx context.Context, tenant string, clientID string, clientSecret string) (string, error) {
	oauthConfig := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     fmt.Sprintf("https://%s/oauth2/token", tenant),
	}

	tokenResponse, err := oauthConfig.Token(ctx)
	if err != nil {
		return "", err
	}

	token := tokenResponse.AccessToken
	return token, nil
}
