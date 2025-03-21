package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/i18n"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
	typesx "github.com/ibm-security-verify/verifyctl/pkg/util/types"
)

const (
	apiAttributes string = "v1.0/attributes"
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
	ID                string            `json:"id,omitempty" yaml:"id,omitempty"`
	Name              string            `json:"name" yaml:"name"`
	Description       string            `json:"description" yaml:"description"`
	Scope             string            `json:"scope,omitempty" yaml:"scope,omitempty"`
	SourceType        string            `json:"sourceType" yaml:"sourceType"`
	DataType          string            `json:"datatype" yaml:"datatype"`
	Tags              []string          `json:"tags" yaml:"tags"`
	Value             string            `json:"value" yaml:"value"`
	CredName          string            `json:"credName" yaml:"credName"`
	CredNameOverrides map[string]string `json:"credNameOverrides" yaml:"credNameOverrides"`
	SchemaAttribute   *SchemaAttribute  `json:"schemaAttribute" yaml:"schemaAttribute"`
	Function          Function          `json:"function" yaml:"function"`
}

type AttributeListResponse struct {
	Limit      int                   `json:"limit,omitempty" yaml:"limit,omitempty"`
	Page       int                   `json:"page,omitempty" yaml:"page,omitempty"`
	Total      int                   `json:"total,omitempty" yaml:"total,omitempty"`
	Count      int                   `json:"count,omitempty" yaml:"count,omitempty"`
	Attributes []*openapi.Attribute0 `json:"attributes" yaml:"attributes"`
}

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, auth *config.AuthConfig, id string) (*openapi.Attribute0, string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	params := openapi.GetAttribute0Params{
		Authorization: fmt.Sprintf("Bearer %s", auth.Token),
	}
	resp, _ := client.GetAttribute0WithResponse(ctx, id, &params)
	if resp.StatusCode() != http.StatusOK {
		vc.Logger.Errorf("unable to get the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the attribute")
	}
	attribute := &openapi.Attribute0{}

	if err := json.Unmarshal(resp.Body, attribute); err != nil {
		fmt.Println(err)
		return nil, "", fmt.Errorf("unable to get the attribute")
	}

	return attribute, auth.Tenant, nil
}

func (c *AttributeClient) GetAttributes(ctx context.Context, auth *config.AuthConfig, search string, sort string, page int, limit int) (
	*AttributeListResponse, string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	params := openapi.GetAllAttributesParams{
		Authorization: fmt.Sprintf("Bearer %s", auth.Token),
	}
	if len(search) > 0 {
		params.Search = &search
	}
	if len(sort) > 0 {
		params.Sort = &sort
	}
	pagination := url.Values{}
	// if page > 0 {
	// 	pagination.Set("page", fmt.Sprintf("%d", page))
	// }

	// if limit > 0 {
	// 	pagination.Set("limit", fmt.Sprintf("%d", limit))
	// }
	// paginationStr := pagination.Encode()
	// if pagination.Encode() != "" {
	// 	params.Pagination = &paginationStr
	// }

	resp, err := client.GetAllAttributesWithResponse(context.Background(), &params)
	var body AttributeListResponse
	if err != nil {
		fmt.Println(err)
	} else {
		if len(pagination) > 0 {
			// skipping this part as we don't have any openapi data type when pagination data are present
		} else {
			if err = json.Unmarshal(resp.Body, &body.Attributes); err != nil {
				vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(resp.Body))
				return nil, "", fmt.Errorf("unable to get the attributes")
			}
		}
	}

	return &body, auth.Tenant, nil
}

// CreateAttribute creates an attribute and returns the resource URI.
func (c *AttributeClient) CreateAttribute(ctx context.Context, auth *config.AuthConfig, attribute *Attribute) (string, error) {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to create attribute.")
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiAttributes))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Conent-Type":   []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	// set some defaults
	if attribute.SchemaAttribute != nil && len(attribute.SchemaAttribute.AttributeName) == 0 && attribute.SchemaAttribute.CustomAttribute {
		attribute.SchemaAttribute.AttributeName = attribute.SchemaAttribute.ScimName
	}

	b, err := json.Marshal(attribute)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the attribute; err=%v", err)
		return "", defaultErr
	}

	response, err := c.client.Post(ctx, u, headers, b)
	if err != nil {
		vc.Logger.Errorf("unable to create attribute; err=%v", err)
		return "", defaultErr
	}
	if response.StatusCode != http.StatusCreated {
		if err := module.HandleCommonErrors(ctx, response, "unable to get attributes"); err != nil {
			vc.Logger.Errorf("unable to create the attribute; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the attribute; code=%d, body=%s", response.StatusCode, string(response.Body))
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
		resourceURI = fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAttributes, id)
	}

	return resourceURI, nil
}

func (c *AttributeClient) UpdateAttribute(ctx context.Context, auth *config.AuthConfig, attribute *Attribute) error {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to update attribute.")

	if len(attribute.ID) == 0 {
		return module.MakeSimpleError(i18n.TranslateWithArgs("'%s' is required", "id"))
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAttributes, attribute.ID))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Conent-Type":   []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(attribute)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the attribute; err=%v", err)
		return defaultErr
	}

	response, err := c.client.Put(ctx, u, headers, b)
	if err != nil {
		vc.Logger.Errorf("unable to update attribute; err=%v", err)
		return defaultErr
	}
	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, response, "unable to get attributes"); err != nil {
			vc.Logger.Errorf("unable to update the attribute; err=%s", err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the attribute; code=%d, body=%s", response.StatusCode, string(response.Body))
		return defaultErr
	}

	return nil
}
