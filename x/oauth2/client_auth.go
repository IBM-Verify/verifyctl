package oauth2

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

type ClientAuth interface {
	GetParameters() (url.Values, error)
}

type ClientSecretPost struct {
	// ClientID contains the client_id of the application or API client configured
	// to use this client authentication method.
	ClientID string

	// ClientSecret contains the client_secret of the application or API client configured
	// to use this client authentication method. It can be left empty for applications that
	// are configured as public clients.
	ClientSecret string
}

func (c *ClientSecretPost) GetParameters() (url.Values, error) {
	ret := url.Values{}
	ret.Add("client_id", c.ClientID)
	if len(c.ClientSecret) > 0 {
		ret.Add("client_secret", c.ClientSecret)
	}

	return ret, nil
}

type PrivateKeyJWT struct {
	// Tenant contains the hostname of the authorization server provided by Verify.
	// This value is expected to be just the hostname and not the scheme or path.
	// Example:
	//
	// 		abc.verify.ibm.com
	Tenant string

	// ClientID contains the client_id of the application or API client configured
	// to use this client authentication method.
	ClientID string

	// PrivateKeyJWK contains the JSONWebKey representation of the private key.
	// The KeyID and Algorithm are expected to be populated.
	PrivateKeyJWK *jose.JSONWebKey

	// Expires optionally specifies how long the token is valid for. By default, this is
	// set to 30 mins.
	Expires time.Duration
}

func (c *PrivateKeyJWT) GetParameters() (url.Values, error) {
	// generate the JWT
	expires := c.Expires
	if c.Expires == 0 {
		expires = 30 * time.Minute
	}

	claims := map[string]interface{}{
		"iss": c.ClientID,
		"sub": c.ClientID,
		"aud": []string{
			fmt.Sprintf("https://%s/oauth2", c.Tenant),
			fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		},
		"exp": time.Now().UTC().Add(expires).Unix(),
		"iat": time.Now().UTC().Unix(),
		"jti": uuid.NewString(),
	}

	h := map[jose.HeaderKey]interface{}{
		jose.HeaderKey("alg"): c.PrivateKeyJWK.Algorithm,
		jose.HeaderKey("typ"): "JWT",
	}

	var token string
	if signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(c.PrivateKeyJWK.Algorithm),
			Key:       c.PrivateKeyJWK,
		}, &jose.SignerOptions{
			ExtraHeaders: h,
		}); err != nil {
		return nil, err
	} else if pbytes, err := json.Marshal(claims); err != nil {
		return nil, fmt.Errorf("marshaling claims failed; err= %v", err)
	} else if o, err := signer.Sign(pbytes); err != nil {
		return nil, err
	} else if token, err = o.CompactSerialize(); err != nil {
		return nil, err
	}

	// add the parameters
	ret := url.Values{}
	ret.Add("client_id", c.ClientID)
	ret.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	ret.Add("client_assertion", token)

	return ret, nil
}
