package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
)

type TokenResponse = openapi.TokenResponse

func GetToken(ctx context.Context, clientId, clientSecret, tenant string) (*TokenResponse, error) {
	formData := url.Values{}
	formData.Add("client_id", clientId)
	formData.Add("client_secret", clientSecret)
	formData.Add("grant_type", "client_credentials")
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", tenant))
	resp, err := client.PostOauth2TokenWithBodyWithResponse(ctx, nil, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	var tokenResponse *TokenResponse
	if err != nil {
		fmt.Println(err)
	} else {
		err = json.Unmarshal(resp.Body, &tokenResponse)
		if err != nil {
			return nil, err
		}
	}
	return tokenResponse, nil
}
