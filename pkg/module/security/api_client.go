package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
	typesx "github.com/ibm-security-verify/verifyctl/pkg/util/types"
)

const (
	apiClients = "v1.0/apiclients"
)

type ApiClient struct {
	client xhttp.Clientx
}

type ApiClientListResponse struct {
	Limit   int       `json:"limit,omitempty" yaml:"limit,omitempty"`
	Page    int       `json:"page,omitempty" yaml:"page,omitempty"`
	Total   int       `json:"total,omitempty" yaml:"total,omitempty"`
	Count   int       `json:"count,omitempty" yaml:"count,omitempty"`
	Clients []*Client `json:"apiclients" yaml:"apiclients"`
}

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

func (c *ApiClient) CreateAPIClient(ctx context.Context, auth *config.AuthConfig, client *Client) (string, error) {
	if client == nil {
		fmt.Println("ERROR: Client object is nil!")
		return "", fmt.Errorf("client object is nil")
	}

	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to create API client")

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiClients))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(client)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal API client data; err=%v", err)
		return "", defaultErr
	}

	response, err := c.client.Post(ctx, u, headers, b)
	if err != nil {
		vc.Logger.Errorf("Unable to create API client; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode != http.StatusCreated {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to create the API client; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the API client; code=%d, body=%s", response.StatusCode, string(response.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	m := map[string]interface{}{}
	resourceURI := ""
	if err := json.Unmarshal(response.Body, &m); err != nil {
		vc.Logger.Warnf("unable to unmarshal the response body to get the 'id'")
		resourceURI = response.Headers.Get("Location")
	} else {
		id := typesx.Map(m).SafeString("id", "")
		resourceURI = fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiClients, id)
	}

	return resourceURI, nil
}

func (c *ApiClient) GetAPIClient(ctx context.Context, auth *config.AuthConfig, clientName string) (*Client, string, error) {
	vc := config.GetVerifyContext(ctx)
	id, err := c.GetAPIClientId(ctx, auth, clientName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiClients, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	vc.Logger.Debugf("Fetching API client with ID %s; URL=%s", id, u.String())
	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API client; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the API client with clientName %s; status=%d", clientName, response.StatusCode)
	}

	Client := &Client{}
	if err = json.Unmarshal(response.Body, Client); err != nil {
		return nil, "", fmt.Errorf("unable to get the API client")
	}

	return Client, u.String(), nil
}

func (c *ApiClient) GetAPIClients(ctx context.Context, auth *config.AuthConfig, search string, sort string, page int, limit int) (
	*ApiClientListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiClients))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	q := u.Query()
	if len(search) > 0 {
		q.Set("search", search)
	}

	if len(sort) > 0 {
		q.Set("sort", sort)
	}

	pagination := url.Values{}
	if page > 0 {
		pagination.Set("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Set("limit", fmt.Sprintf("%d", limit))
	}

	if len(pagination) > 0 {
		q.Set("pagination", pagination.Encode())
	}

	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the API clients; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get API clients"); err != nil {
			vc.Logger.Errorf("unable to get the API clients; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API clients; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the API clients")
	}

	apiclientsResponse := &ApiClientListResponse{}
	if err = json.Unmarshal(response.Body, &apiclientsResponse); err != nil {
		vc.Logger.Errorf("unable to get the API clients; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the API clients")
	}

	return apiclientsResponse, u.String(), nil
}

func (c *ApiClient) UpdateAPIClient(ctx context.Context, auth *config.AuthConfig, client *Client) error {
	vc := config.GetVerifyContext(ctx)
	if client == nil {
		vc.Logger.Errorf("client object is nil")
		return fmt.Errorf("client object is nil")
	}

	id, err := c.GetAPIClientId(ctx, auth, client.ClientName)
	if err != nil {
		vc.Logger.Errorf("unable to get the client ID for API client '%s'; err=%s", client.ClientName, err.Error())
		return fmt.Errorf("unable to get the client ID for API client '%s'; err=%s", client.ClientName, err.Error())
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiClients, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(client)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the API client; err=%v", err)
		return fmt.Errorf("unable to marshal the API client; err=%v", err)
	}

	response, err := c.client.Put(ctx, u, headers, b)
	if err != nil {
		vc.Logger.Errorf("unable to update API client; err=%v", err)
		return fmt.Errorf("unable to update API client; err=%v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		vc.Logger.Errorf("failed to update API client; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("failed to update API client ; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil

}

func (c *ApiClient) GetAPIClientId(ctx context.Context, auth *config.AuthConfig, clientName string) (string, error) {
	vc := config.GetVerifyContext(ctx)
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiClients))
	q := u.Query()
	q.Set("search", fmt.Sprintf(`clientName contains "%s"`, clientName))
	u.RawQuery = q.Encode()

	response, err := c.client.Get(ctx, u, headers)

	if err != nil {
		vc.Logger.Errorf("unable to query API clients; err=%s", err.Error())
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
			return "", fmt.Errorf("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
		}

		vc.Logger.Errorf("unable to get API client ID; code=%d, body=%s", response.StatusCode, string(response.Body))
		return "", fmt.Errorf("unable to get API client ID with clientName %s; status=%d", clientName, response.StatusCode)

	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		vc.Logger.Errorf("failed to parse API response; err=%s", err.Error())
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	apiClients, ok := data["apiClients"].([]interface{})
	if !ok || len(apiClients) == 0 {
		vc.Logger.Infof("no API client found with clientName %s", clientName)
		return "", fmt.Errorf("no API client found with clientName %s", clientName)
	}

	for _, resource := range apiClients {
		client, ok := resource.(map[string]interface{})
		if !ok {
			vc.Logger.Errorf("invalid client format in API response")
			return "", fmt.Errorf("invalid client format in API response")
		}

		name, ok := client["clientName"].(string)
		if !ok {
			vc.Logger.Errorf("clientName not found or invalid type in API response")
			return "", fmt.Errorf("clientName not found or invalid type in API response")
		}

		if name == clientName {
			id, ok := client["id"].(string)
			if !ok {
				vc.Logger.Errorf("ID not found or invalid type in API response")
				return "", fmt.Errorf("ID not found or invalid type in API response")
			}
			vc.Logger.Debugf("Resolved clientName %s to ID %s", clientName, id)
			return id, nil
		}
	}

	vc.Logger.Infof("no exact match found for clientName %s", clientName)
	return "", fmt.Errorf("no API client found with exact clientName %s", clientName)
}

func (c *ApiClient) DeleteAPIClient(ctx context.Context, auth *config.AuthConfig, clientName string) error {
	vc := config.GetVerifyContext(ctx)

	id, err := c.GetAPIClientId(ctx, auth, clientName)
	if err != nil {
		vc.Logger.Errorf("unable to resolve API client ID for clientName %s; err=%s", clientName, err.Error())
		return err
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiClients, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Delete(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to delete API client; err=%s", err.Error())
		return fmt.Errorf("unable to delete the API client; err=%s", err.Error())
	}

	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to delete API client"); err != nil {
			vc.Logger.Errorf("unable to delete the API client; err=%s", err.Error())
			return fmt.Errorf("unable to delete the API client; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *ApiClient) DeleteAPIClientById(ctx context.Context, auth *config.AuthConfig, id string) error {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiClients, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}
	response, err := c.client.Delete(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to delete API client; err=%s", err.Error())
		return fmt.Errorf("unable to delete the API client; err=%s", err.Error())
	}
	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to delete API client"); err != nil {
			vc.Logger.Errorf("unable to delete the API client; err=%s", err.Error())
			return fmt.Errorf("unable to delete the API client; err=%s", err.Error())
		}
		vc.Logger.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode, string(response.Body))
	}
	return nil
}
