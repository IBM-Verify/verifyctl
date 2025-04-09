package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
)

const (
	apiIdentitysources = "v2.0/identitysources"
)

type IdentitysourceClient struct {
	client xhttp.Clientx
}

type IdentitysourceListResponse struct {
	TotalResults    int              `json:"total" yaml:"total"`
	Identitysources []IdentitySource `json:"identitySources" yaml:"identitySources"`
}

type IdentitySource struct {
	SourceTypeID      int                `json:"sourceTypeId" yaml:"sourceTypeId"`
	InstanceName      string             `json:"instanceName" yaml:"instanceName"`
	Enabled           bool               `json:"enabled" yaml:"enabled"`
	Status            string             `json:"status,omitempty" yaml:"status,omitempty"`
	Predefined        bool               `json:"predefined,omitempty" yaml:"predefined,omitempty"`
	Properties        []Property         `json:"properties" yaml:"properties"`
	AttributeMappings []AttributeMapping `json:"attributeMappings,omitempty" yaml:"attributeMappings,omitempty"`
}

type Property struct {
	Sensitive bool   `json:"sensitive" yaml:"sensitive"`
	Key       string `json:"key" yaml:"key"`
	Value     string `json:"value" yaml:"value"`
}

type AttributeMapping struct {
	AttrID      string    `json:"attrId" yaml:"attrId"`
	JitpOption  string    `json:"jitpOption" yaml:"jitpOption"`
	IdsAttrName string    `json:"idsAttrName" yaml:"idsAttrName"`
	PostEval    *PostEval `json:"postEval,omitempty" yaml:"postEval,omitempty"`
}

type PostEval struct {
	ID     string `json:"id,omitempty" yaml:"id,omitempty"`
	Custom string `json:"custom,omitempty" yaml:"custom,omitempty"`
}

func NewIdentitySourceClient() *IdentitysourceClient {
	return &IdentitysourceClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *IdentitysourceClient) CreateIdentitysource(ctx context.Context, auth *config.AuthConfig, identitysource *IdentitySource) (string, error) {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to create identitysource.")
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiIdentitysources))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(identitysource)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal identitysource data; err=%v", err)
		return "", defaultErr
	}

	response, err := c.client.Post(ctx, u, headers, b)

	if err != nil {
		vc.Logger.Errorf("Unable to create identitysource; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode != http.StatusCreated {
		if err := module.HandleCommonErrors(ctx, response, "unable to create identitysource"); err != nil {
			vc.Logger.Errorf("unable to create the identitysource; err=%s", err.Error())
			return "", fmt.Errorf("unable to create the identitysource; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the identitysource; code=%d, body=%s", response.StatusCode, string(response.Body))
		return "", fmt.Errorf("unable to create the identitysource; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return "Identity provider created successfully", nil
}

func (c *IdentitysourceClient) GetIdentitysource(ctx context.Context, auth *config.AuthConfig, identitysourceName string) (*IdentitySource, string, error) {
	vc := config.GetVerifyContext(ctx)
	id, err := c.getIdentitysourceId(ctx, auth, identitysourceName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiIdentitysources, id))

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the IdentitySource; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the IdentitySource")
	}

	IdentitySource := &IdentitySource{}
	if err = json.Unmarshal(response.Body, IdentitySource); err != nil {
		return nil, "", fmt.Errorf("unable to get the IdentitySource")
	}

	return IdentitySource, u.String(), nil
}

func (c *IdentitysourceClient) GetIdentitysources(ctx context.Context, auth *config.AuthConfig, sort string, count string) (
	*IdentitysourceListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiIdentitysources))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	q := u.Query()

	if len(sort) > 0 {
		q.Set("sort", sort)
	}

	if len(count) > 0 {
		q.Set("count", count)
	}

	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}

	response, err := c.client.Get(ctx, u, headers)

	if err != nil {
		vc.Logger.Errorf("unable to get the Identitysources; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get Identitysources"); err != nil {
			vc.Logger.Errorf("unable to get the Identitysources; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Identitysources; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Identitysources")
	}

	IdentitysourcesResponse := &IdentitysourceListResponse{}
	if err = json.Unmarshal(response.Body, &IdentitysourcesResponse); err != nil {
		vc.Logger.Errorf("unable to get the Identitysources; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Identitysources")
	}

	return IdentitysourcesResponse, u.String(), nil
}

func (c *IdentitysourceClient) DeleteIdentitysource(ctx context.Context, auth *config.AuthConfig, name string) error {
	vc := config.GetVerifyContext(ctx)

	id, err := c.getIdentitysourceId(ctx, auth, name)
	if err != nil {
		vc.Logger.Errorf("unable to get the identitysource ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the identitysource ID; err=%s", err.Error())
	}

	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiIdentitysources, id))

	response, err := c.client.Delete(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		return fmt.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
	}

	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, response, "unable to delete IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
			return fmt.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the IdentitySource; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to delete the IdentitySource; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *IdentitysourceClient) UpdateIdentitysource(ctx context.Context, auth *config.AuthConfig, identitysource *IdentitySource) error {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to update identitysource.")

	id, err := c.getIdentitysourceId(ctx, auth, identitysource.InstanceName)
	if err != nil {
		vc.Logger.Errorf("unable to get the identitysource ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the identitysource ID; err=%s", err.Error())
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiIdentitysources, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(identitysource)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal identitysource data; err=%v", err)
		return defaultErr
	}

	response, err := c.client.Put(ctx, u, headers, b)

	if err != nil {
		vc.Logger.Errorf("unable to update identitysource; err=%v", err)
		return fmt.Errorf("unable to update identitysource; err=%v", err)
	}

	if response.StatusCode != http.StatusNoContent {
		vc.Logger.Errorf("failed to update identitysource; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("failed to update identitysource ; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *IdentitysourceClient) getIdentitysourceId(ctx context.Context, auth *config.AuthConfig, name string) (string, error) {
	vc := config.GetVerifyContext(ctx)
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiIdentitysources))
	q := u.Query()
	q.Set("search", fmt.Sprintf(`instanceName = "%s"`, name))
	u.RawQuery = q.Encode()

	response, _ := c.client.Get(ctx, u, headers)

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySource with identitysourceName %s; err=%s", name, err.Error())
			return "", fmt.Errorf("unable to get the IdentitySource with identitysourceName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	resources, ok := data["identitySources"].([]interface{})
	if !ok || len(resources) == 0 {
		return "", fmt.Errorf("no identitysource found with identitysourceName %s", name)
	}

	firstResource, ok := resources[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid resource format")
	}

	// Extract "id" field
	id, ok := firstResource["id"].(string)
	if !ok {
		return "", fmt.Errorf("ID not found or invalid type")
	}

	return id, nil
}
