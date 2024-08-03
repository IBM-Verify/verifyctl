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

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, auth *config.AuthConfig, id string) (*Attribute, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAttributes, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the attribute; err=%s", err.Error())
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get attribute"); err != nil {
			vc.Logger.Errorf("unable to get the attribute; err=%s", err.Error())
			return nil, err
		}

		return nil, fmt.Errorf("unable to get the attribute")
	}

	attribute := &Attribute{}
	if err = json.Unmarshal(response.Body, attribute); err != nil {
		return nil, fmt.Errorf("unable to get the attribute")
	}

	return attribute, nil
}
