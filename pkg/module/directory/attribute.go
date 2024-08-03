package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
)

const (
	apiAttributes string = "attrservice.mgt/v1.0/attributes"
)

type AttributeClient struct {
	client *http.Client
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

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{
		client: http.DefaultClient,
	}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, auth *config.AuthConfig, id string) (*Attribute, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAttributes, id), nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", "application/json")
	request.Header.Add("Authorization", "Bearer "+auth.Token)

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("Login again.")
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Unable to get the attributes")
	}

	resBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Unable to get the attributes")
	}

	attribute := &Attribute{}
	if err = json.Unmarshal(resBody, attribute); err != nil {
		return nil, fmt.Errorf("Unable to get the attributes")
	}

	return attribute, nil
}
