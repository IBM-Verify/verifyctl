package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
)

type IdentitysourceClient struct{}

type IdentitySource = openapi.IdentitySourceInstancesData
type IdentitySourceList = openapi.IdentitySourceIntancesDataList

func NewIdentitySourceClient() *IdentitysourceClient {
	return &IdentitysourceClient{}
}

func (c *IdentitysourceClient) CreateIdentitysource(ctx context.Context, auth *config.AuthConfig, identitysource *IdentitySource) (string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	defaultErr := fmt.Errorf("unable to create identitysource")

	body, err := json.Marshal(identitysource)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal identitysource data; err=%v", err)
		return "", defaultErr
	}

	resp, err := client.CreateIdentitySourceV2WithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("Unable to create identitysource; err=%v", err)
		return "", defaultErr
	}

	if resp.StatusCode() != http.StatusCreated {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to create identitysource"); err != nil {
		// 	vc.Logger.Errorf("unable to create the identitysource; err=%s", err.Error())
		// 	return "", fmt.Errorf("unable to create the identitysource; err=%s", err.Error())
		// }

		vc.Logger.Errorf("unable to create the identitysource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", fmt.Errorf("unable to create the identitysource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return "Identity provider created successfully", nil
}

func (c *IdentitysourceClient) GetIdentitysource(ctx context.Context, auth *config.AuthConfig, identitysourceName string) (*IdentitySource, string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	id, err := c.getIdentitysourceId(ctx, auth, identitysourceName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	resp, err := client.GetInstanceV2WithResponse(ctx, id, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer "+auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to get IdentitySource"); err != nil {
		// 	vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
		// 	return nil, "", err
		// }

		vc.Logger.Errorf("unable to get the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the IdentitySource")
	}

	IdentitySource := &IdentitySource{}
	if err = json.Unmarshal(resp.Body, IdentitySource); err != nil {
		return nil, "", fmt.Errorf("unable to get the IdentitySource")
	}

	return IdentitySource, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *IdentitysourceClient) GetIdentitysources(ctx context.Context, auth *config.AuthConfig, sort string, count string) (*IdentitySourceList, string, error) {

	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	params := &openapi.GetInstancesV2Params{}
	if len(sort) > 0 {
		params.Sort = &sort
	}
	if len(count) > 0 {
		params.Count = &count
	}

	resp, err := client.GetInstancesV2WithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to get the Identitysources; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to get Identitysources"); err != nil {
		// 	vc.Logger.Errorf("unable to get the Identitysources; err=%s", err.Error())
		// 	return nil, "", err
		// }

		vc.Logger.Errorf("unable to get the Identitysources; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Identitysources")
	}

	IdentitysourcesResponse := &IdentitySourceList{}
	if err = json.Unmarshal(resp.Body, &IdentitysourcesResponse); err != nil {
		vc.Logger.Errorf("unable to get the Identitysources; err=%s, body=%s", err, string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Identitysources")
	}

	return IdentitysourcesResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *IdentitysourceClient) DeleteIdentitysource(ctx context.Context, auth *config.AuthConfig, name string) error {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	id, err := c.getIdentitysourceId(ctx, auth, name)
	if err != nil {
		vc.Logger.Errorf("unable to get the identitysource ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the identitysource ID; err=%s", err.Error())
	}

	resp, err := client.DeleteIdentitySourceV2WithResponse(ctx, id, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		return fmt.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		// if err := module.HandleCommonErrors(ctx, response, "unable to delete IdentitySource"); err != nil {
		// 	vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		// 	return fmt.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		// }

		vc.Logger.Errorf("unable to delete the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return fmt.Errorf("unable to delete the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *IdentitysourceClient) UpdateIdentitysource(ctx context.Context, auth *config.AuthConfig, identitysource *IdentitySource) error {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	defaultErr := fmt.Errorf("unable to update identitysource")
	id, err := c.getIdentitysourceId(ctx, auth, identitysource.InstanceName)
	fmt.Println(id)
	if err != nil {
		vc.Logger.Errorf("unable to get the identitysource ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the identitysource ID; err=%s", err.Error())
	}
	body, err := json.Marshal(identitysource)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal identitysource data; err=%v", err)
		return defaultErr
	}

	resp, err := client.UpdateIdentitySourceV2WithBodyWithResponse(ctx, id, "application/json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to update identitysource; err=%v", err)
		return fmt.Errorf("unable to update identitysource; err=%v", err)
	}

	if resp.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update identitysource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return fmt.Errorf("failed to update identitysource ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *IdentitysourceClient) getIdentitysourceId(ctx context.Context, auth *config.AuthConfig, name string) (string, error) {
	// vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	search := fmt.Sprintf(`instanceName = "%s"`, name)
	params := &openapi.GetInstancesV2Params{
		Search: &search,
	}
	resp, _ := client.GetInstancesV2WithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, response, "unable to get IdentitySource"); err != nil {
		// vc.Logger.Errorf("unable to get the IdentitySource with identitysourceName %s; err=%s", name, err.Error())
		// return "", fmt.Errorf("unable to get the IdentitySource with identitysourceName %s; err=%s", name, err.Error())
		// }

		// Later need to remove this return
		return "", fmt.Errorf("unable to get the IdentitySource with identitysourceName %s", name)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
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
