package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	typesx "github.com/ibm-verify/verify-sdk-go/x/types"
	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/module/openapi"
	xhttp "github.com/ibm-verify/verifyctl/pkg/util/http"
)

type ApiClient struct {
	client xhttp.Clientx
}

type APIClientListResponse = openapi.APIClientConfigPaginatedResponseContainer
type APIClientConfig = openapi.APIClientConfig
type Client struct {
	ID               string                 `yaml:"id,omitempty" json:"id,omitempty"`
	ClientID         string                 `yaml:"clientId,omitempty" json:"clientId,omitempty"`
	ClientName       string                 `yaml:"clientName" json:"clientName"`
	ClientSecret     string                 `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`
	Entitlements     []string               `yaml:"entitlements" json:"entitlements"`
	Enabled          bool                   `yaml:"enabled" json:"enabled"`
	OverrideSettings OverrideSettings       `yaml:"overrideSettings,omitempty" json:"overrideSettings,omitempty"`
	Description      string                 `yaml:"description,omitempty" json:"description,omitempty"`
	IPFilterOp       string                 `yaml:"ipFilterOp,omitempty" json:"ipFilterOp,omitempty"`
	IPFilters        []string               `yaml:"ipFilters,omitempty" json:"ipFilters,omitempty"`
	JWKUri           string                 `yaml:"jwkUri,omitempty" json:"jwkUri,omitempty"`
	AdditionalConfig AdditionalConfig       `yaml:"additionalConfig,omitempty" json:"additionalConfig,omitempty"`
	AdditionalProps  map[string]interface{} `yaml:"additionalProperties,omitempty" json:"additionalProperties,omitempty"`
}

type OverrideSettings struct {
	RestrictScopes bool    `yaml:"restrictScopes" json:"restrictScopes"`
	Scopes         []Scope `yaml:"scopes" json:"scopes"`
}

type Scope struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
}

type AdditionalConfig struct {
	ClientAuthMethod                       string   `yaml:"clientAuthMethod" json:"clientAuthMethod"`
	ValidateClientAssertionJti             bool     `yaml:"validateClientAssertionJti" json:"validateClientAssertionJti"`
	AllowedClientAssertionVerificationKeys []string `yaml:"allowedClientAssertionVerificationKeys,omitempty" json:"allowedClientAssertionVerificationKeys,omitempty"`
}

func NewAPIClient() *ApiClient {
	return &ApiClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *ApiClient) CreateAPIClient(ctx context.Context, auth *config.AuthConfig, apiClientConfig *APIClientConfig) (string, error) {
	if apiClientConfig == nil {
		fmt.Println("ERROR: Client object is nil!")
		return "", errorsx.G11NError("client object is nil")
	}

	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to create API client")
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))

	body, err := json.Marshal(apiClientConfig)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal API client data; err=%v", err)
		return "", defaultErr
	}

	response, err := client.CreateAPIClientWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("Unable to create API client; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to create the API client; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	m := map[string]interface{}{}
	resourceURI := ""
	if err := json.Unmarshal(response.Body, &m); err != nil {
		vc.Logger.Warnf("unable to unmarshal the response body to get the 'id'")
		resourceURI = response.HTTPResponse.Header.Get("Location")
	} else {
		id := typesx.Map(m).SafeString("id", "")
		resourceURI = fmt.Sprintf("%s/%s", response.HTTPResponse.Request.URL.String(), id)
	}

	return resourceURI, nil
}

func (c *ApiClient) GetAPIClient(ctx context.Context, auth *config.AuthConfig, clientName string) (*APIClientConfig, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	id, err := c.GetAPIClientId(ctx, auth, clientName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	response, err := client.GetAPIClientWithResponse(ctx, id, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API client with clientName %s; status=%d", clientName, response.StatusCode())
	}

	Client := &APIClientConfig{}
	if err = json.Unmarshal(response.Body, Client); err != nil {
		return nil, "", errorsx.G11NError("unable to get the API client")
	}

	return Client, response.HTTPResponse.Request.URL.String(), nil
}

func (c *ApiClient) GetAPIClients(ctx context.Context, auth *config.AuthConfig, search string, sort string, page int, limit int) (*APIClientListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	params := &openapi.GetAPIClientsParams{}
	if len(search) > 0 {
		params.Search = &search
	}
	if len(sort) > 0 {
		params.Sort = &sort
	}

	pagination := url.Values{}
	if page > 0 {
		pagination.Set("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Set("limit", fmt.Sprintf("%d", limit))
	}

	if len(pagination) > 0 {
		paginationStr := pagination.Encode()
		params.Pagination = &paginationStr
	}

	response, err := client.GetAPIClientsWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to get the API clients; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API clients"); err != nil {
			vc.Logger.Errorf("unable to get the API clients; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API clients; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API clients")
	}

	apiclientsResponse := &APIClientListResponse{}
	if err = json.Unmarshal(response.Body, &apiclientsResponse); err != nil {
		vc.Logger.Errorf("unable to get the API clients; err=%s, body=%s", err, string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API clients")
	}

	return apiclientsResponse, response.HTTPResponse.Request.URL.String(), nil
}

func (c *ApiClient) UpdateAPIClient(ctx context.Context, auth *config.AuthConfig, apiClientConfig *APIClientConfig) error {
	vc := contextx.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	if apiClientConfig == nil {
		vc.Logger.Errorf("client object is nil")
		return errorsx.G11NError("client object is nil")
	}
	fmt.Println(apiClientConfig.ClientName)
	id, err := c.GetAPIClientId(ctx, auth, apiClientConfig.ClientName)
	if err != nil {
		vc.Logger.Errorf("unable to get the client ID for API client '%s'; err=%s", apiClientConfig.ClientName, err.Error())
		return errorsx.G11NError("unable to get the client ID for API client '%s'; err=%s", apiClientConfig.ClientName, err.Error())
	}

	body, err := json.Marshal(apiClientConfig)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the API client; err=%v", err)
		return errorsx.G11NError("unable to marshal the API client; err=%v", err)
	}

	response, err := client.UpdateAPIClientWithBodyWithResponse(ctx, id, "application/json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to update API client; err=%v", err)
		return errorsx.G11NError("unable to update API client; err=%v", err)
	}
	if response.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("failed to update API client ; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil

}

func (c *ApiClient) GetAPIClientId(ctx context.Context, auth *config.AuthConfig, clientName string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))

	search := fmt.Sprintf(`clientName contains "%s"`, clientName)
	params := &openapi.GetAPIClientsParams{
		Search: &search,
	}

	response, err := client.GetAPIClientsWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to query API clients; err=%s", err.Error())
		return "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
			return "", errorsx.G11NError("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
		}

		vc.Logger.Errorf("unable to get API client ID; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", errorsx.G11NError("unable to get API client ID with clientName %s; status=%d", clientName, response.StatusCode())

	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		vc.Logger.Errorf("failed to parse API response; err=%s", err.Error())
		return "", errorsx.G11NError("failed to parse API response: %w", err)
	}

	apiClients, ok := data["apiClients"].([]interface{})
	if !ok || len(apiClients) == 0 {
		vc.Logger.Infof("no API client found with clientName %s", clientName)
		return "", errorsx.G11NError("no API client found with clientName %s", clientName)
	}

	for _, resource := range apiClients {
		client, ok := resource.(map[string]interface{})
		if !ok {
			vc.Logger.Errorf("invalid client format in API response")
			return "", errorsx.G11NError("invalid client format in API response")
		}

		name, ok := client["clientName"].(string)
		if !ok {
			vc.Logger.Errorf("clientName not found or invalid type in API response")
			return "", errorsx.G11NError("clientName not found or invalid type in API response")
		}

		if name == clientName {
			id, ok := client["id"].(string)
			if !ok {
				vc.Logger.Errorf("ID not found or invalid type in API response")
				return "", errorsx.G11NError("ID not found or invalid type in API response")
			}
			vc.Logger.Debugf("Resolved clientName %s to ID %s", clientName, id)
			return id, nil
		}
	}

	vc.Logger.Infof("no exact match found for clientName %s", clientName)
	return "", errorsx.G11NError("no API client found with exact clientName %s", clientName)
}

func (c *ApiClient) DeleteAPIClientById(ctx context.Context, auth *config.AuthConfig, id string) error {
	vc := contextx.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	response, err := client.DeleteAPIClientWithResponse(ctx, id, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to delete API client; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the API client; err=%s", err.Error())
	}
	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete API client"); err != nil {
			vc.Logger.Errorf("unable to delete the API client; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the API client; err=%s", err.Error())
		}
		vc.Logger.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("unable to delete the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}
	return nil
}
