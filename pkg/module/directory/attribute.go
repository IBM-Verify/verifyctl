package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/i18n"
	"github.com/ibm-verify/verifyctl/pkg/module"
	"github.com/ibm-verify/verifyctl/pkg/module/openapi"
	typesx "github.com/ibm-verify/verifyctl/pkg/util/types"
)

type AttributeClient struct{}

type Attribute = openapi.Attribute0
type AttributeList = openapi.PaginatedAttribute0

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, auth *config.AuthConfig, id string) (*Attribute, string, error) {
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
	attribute := &Attribute{}

	if err := json.Unmarshal(resp.Body, attribute); err != nil {
		fmt.Println(err)
		return nil, "", fmt.Errorf("unable to get the attribute")
	}

	return attribute, auth.Tenant, nil
}

func (c *AttributeClient) GetAttributes(ctx context.Context, auth *config.AuthConfig, search string, sort string, page int, limit int) (*AttributeList, string, error) {
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
	if page > 0 {
		pagination.Set("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Set("limit", fmt.Sprintf("%d", limit))
	}
	paginationStr := pagination.Encode()
	if pagination.Encode() != "" {
		params.Pagination = &paginationStr
	}

	resp, err := module.CustomParse(client.GetAllAttributes(ctx, &params))
	body := &AttributeList{}
	if err != nil {
		fmt.Println(err)
	} else {
		if len(pagination) > 0 {
			if err = json.Unmarshal(resp.Body, &body); err != nil {
				vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(resp.Body))
				return nil, "", fmt.Errorf("unable to get the attributes")
			}
		} else {
			if err = json.Unmarshal(resp.Body, &body.Attributes); err != nil {
				vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(resp.Body))
				return nil, "", fmt.Errorf("unable to get the attributes")
			}
		}
	}

	return body, auth.Tenant, nil
}

// CreateAttribute creates an attribute and returns the resource URI.
func (c *AttributeClient) CreateAttribute(ctx context.Context, auth *config.AuthConfig, attribute *Attribute) (string, error) {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to create attribute")
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	params := &openapi.CreateAttributeParams{
		Authorization: fmt.Sprintf("Bearer %s", auth.Token),
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
	resp, err := client.CreateAttributeWithBodyWithResponse(ctx, params, "application/json", bytes.NewReader(b))
	if err != nil {
		vc.Logger.Errorf("unable to create attribute; err=%v", err)
		return "", defaultErr
	}
	if resp.StatusCode() != http.StatusCreated {
		if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get attributes"); err != nil {
			vc.Logger.Errorf("unable to create the attribute; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	m := map[string]interface{}{}
	resourceURI := ""
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		vc.Logger.Warnf("unable to unmarshal the response body to get the 'id'")
		resourceURI = resp.HTTPResponse.Header.Get("Location")
	} else {
		id := typesx.Map(m).SafeString("id", "")
		resourceURI = resp.HTTPResponse.Request.URL.JoinPath(id).String()
	}
	return resourceURI, nil
}

func (c *AttributeClient) UpdateAttribute(ctx context.Context, auth *config.AuthConfig, attribute *Attribute) error {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to update attribute")
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))

	if len(*attribute.ID) == 0 {
		return module.MakeSimpleError(i18n.TranslateWithArgs("'%s' is required", "id"))
	}
	params := &openapi.UpdateAttributeParams{
		Authorization: fmt.Sprintf("Bearer %s", auth.Token),
	}
	body, err := json.Marshal(attribute)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the attribute; err=%v", err)
		return defaultErr
	}
	resp, err := client.UpdateAttributeWithBodyWithResponse(ctx, *attribute.ID, params, "application/json", bytes.NewReader(body))
	if err != nil {
		vc.Logger.Errorf("unable to update attribute; err=%v", err)
		return defaultErr
	}
	if resp.StatusCode() != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get attributes"); err != nil {
			vc.Logger.Errorf("unable to update the attribute; err=%s", err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return defaultErr
	}

	return nil
}
