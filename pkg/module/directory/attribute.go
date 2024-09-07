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
	apiAttributes string = "attrservice.mgt/v1.0/attributes"
)

type AttributeClient struct {
	client xhttp.Clientx
}

// SchemaAttribute is the domain model defining the properties of schema attribute
type SchemaAttribute struct {
	Name            string `json:"name" yaml:"name"`
	AttributeName   string `json:"attributeName" yaml:"attributeName"`
	ScimName        string `json:"scimName" yaml:"scimName"`
	CustomAttribute bool   `json:"customAttribute" yaml:"customAttribute"`
}

// Function is the domain model holding the definition of custom and simple attribute functions
type Function struct {
	Name   string `json:"name" yaml:"name"`
	Custom string `json:"custom" yaml:"custom"`
}

// Attribute is the domain model defining an attribute
type Attribute struct {
	ID                string            `json:"id" yaml:"id"`
	Name              string            `json:"name" yaml:"name"`
	Description       string            `json:"description" yaml:"description"`
	Scope             string            `json:"scope" yaml:"scope"`
	SourceType        string            `json:"sourceType" yaml:"sourceType"`
	DataType          string            `json:"datatype" yaml:"datatype"`
	Tags              []string          `json:"tags" yaml:"tags"`
	Value             string            `json:"value" yaml:"value"`
	CredName          string            `json:"credName" yaml:"credName"`
	CredNameOverrides map[string]string `json:"credNameOverrides" yaml:"credNameOverrides"`
	SchemaAttribute   SchemaAttribute   `json:"schemaAttribute" yaml:"schemaAttribute"`
	Function          Function          `json:"function" yaml:"function"`
}

type AttributeListResponse struct {
	Limit      int          `json:"limit,omitempty" yaml:"limit,omitempty"`
	Page       int          `json:"page,omitempty" yaml:"page,omitempty"`
	Total      int          `json:"total,omitempty" yaml:"total,omitempty"`
	Count      int          `json:"count,omitempty" yaml:"count,omitempty"`
	Attributes []*Attribute `json:"attributes" yaml:"attributes"`
}

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, auth *config.AuthConfig, id string) (*Attribute, string, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAttributes, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the attribute; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get attribute"); err != nil {
			vc.Logger.Errorf("unable to get the attribute; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the attribute; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the attribute")
	}

	attribute := &Attribute{}
	if err = json.Unmarshal(response.Body, attribute); err != nil {
		return nil, "", fmt.Errorf("unable to get the attribute")
	}

	return attribute, u.String(), nil
}

func (c *AttributeClient) GetAttributes(ctx context.Context, auth *config.AuthConfig, search string, sort string, page int, limit int) (
	*AttributeListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiAttributes))
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
		vc.Logger.Errorf("unable to get the attributes; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get attributes"); err != nil {
			vc.Logger.Errorf("unable to get the attributes; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the attributes; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the attributes")
	}

	attributesResponse := &AttributeListResponse{}
	if err = json.Unmarshal(response.Body, &attributesResponse); err != nil {
		vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the attributes")
	}

	return attributesResponse, u.String(), nil
}

// CreateAttribute creates an attribute and returns the resource URI.
func (c *AttributeClient) CreateAttribute(ctx context.Context, auth *config.AuthConfig, attribute *Attribute) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (c *AttributeClient) UpdateAttribute(ctx context.Context, auth *config.AuthConfig, attribute *Attribute) error {
	return fmt.Errorf("not implemented")
}
