package oauth2

import (
	"context"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/ibm-verify/verifyctl/x/randx"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	Tenant string

	ClientAuth ClientAuth

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	Scopes []string
}

type AuthorizeResponse struct {
	State string

	AuthCodeURL string

	PKCECodeVerifier string
}

func (c *Client) TokenWithAPIClient(ctx context.Context, parameters url.Values) (*oauth2.Token, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	clientID := params.Get("client_id")
	params.Del("client_id")
	clientSecret := params.Get("client_secret")
	params.Del("client_secret")

	for k := range parameters {
		params.Add(k, parameters.Get(k))
	}

	oauthConfig := &clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		AuthStyle:      oauth2.AuthStyleInParams,
		EndpointParams: params,
		Scopes:         c.Scopes,
	}

	return oauthConfig.Token(ctx)
}

func (c *Client) AuthorizeWithBrowserFlow(ctx context.Context, parameters url.Values) (*AuthorizeResponse, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	for k := range parameters {
		opts = append(opts, oauth2.SetAuthURLParam(k, parameters.Get(k)))
	}

	verifier := oauth2.GenerateVerifier()
	opts = append(opts, oauth2.S256ChallengeOption(verifier))

	oauthConfig := &oauth2.Config{
		ClientID: params.Get("client_id"),
		Endpoint: oauth2.Endpoint{
			AuthURL: fmt.Sprintf("https://%s/oauth2/authorize", c.Tenant),
		},
		RedirectURL: c.RedirectURL,
		Scopes:      c.Scopes,
	}

	state, err := randx.GenerateRandomString(24, randx.AlphaLower)
	if err != nil {
		// this should never happen, but if it does, this falls back to a UUID.
		state = uuid.NewString()
	}

	return &AuthorizeResponse{
		State:            state,
		AuthCodeURL:      oauthConfig.AuthCodeURL(state, opts...),
		PKCECodeVerifier: verifier,
	}, nil
}

func (c *Client) TokenWithAuthCode(ctx context.Context, authResponse *AuthorizeResponse, callbackParams url.Values) (*oauth2.Token, error) {
	// verify if the flow has failed
	if callbackParams.Get("error") != "" {
		return nil, fmt.Errorf("error: %s, description: %s", callbackParams.Get("error"), callbackParams.Get("error_description"))
	}

	// check if the state matches
	if callbackParams.Get("state") != authResponse.State {
		return nil, fmt.Errorf("'state' does not match.")
	}

	// do the biz
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	clientID := params.Get("client_id")
	params.Del("client_id")
	clientSecret := params.Get("client_secret")
	params.Del("client_secret")

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/oauth2/authorize", c.Tenant),
			TokenURL: fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		},
		Scopes:      c.Scopes,
		RedirectURL: c.RedirectURL,
	}

	var opts []oauth2.AuthCodeOption
	if len(params) > 0 {
		for k := range params {
			opts = append(opts, oauth2.SetAuthURLParam(k, params.Get(k)))
		}
	}

	opts = append(opts, oauth2.VerifierOption(authResponse.PKCECodeVerifier))
	return oauthConfig.Exchange(ctx, callbackParams.Get("code"), opts...)
}

func (c *Client) AuthorizeWithDeviceFlow(ctx context.Context, parameters url.Values) (*oauth2.DeviceAuthResponse, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	for k := range parameters {
		opts = append(opts, oauth2.SetAuthURLParam(k, parameters.Get(k)))
	}

	oauthConfig := &oauth2.Config{
		ClientID: params.Get("client_id"),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: fmt.Sprintf("https://%s/oauth2/device_authorization", c.Tenant),
		},
		Scopes: c.Scopes,
	}

	return oauthConfig.DeviceAuth(ctx, opts...)
}

func (c *Client) TokenWithDeviceFlow(ctx context.Context, deviceAuthResponse *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	clientID := params.Get("client_id")
	params.Del("client_id")
	clientSecret := params.Get("client_secret")
	params.Del("client_secret")

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: fmt.Sprintf("https://%s/oauth2/device_authorization", c.Tenant),
			TokenURL:      fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		},
		Scopes: c.Scopes,
	}

	var opts []oauth2.AuthCodeOption
	if len(params) > 0 {
		for k := range params {
			opts = append(opts, oauth2.SetAuthURLParam(k, params.Get(k)))
		}
	}

	return oauthConfig.DeviceAccessToken(ctx, deviceAuthResponse, opts...)
}
