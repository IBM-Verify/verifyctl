package branding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
)

const (
	apiThemes string = "v1.0/branding/themes"
)

type ThemeClient struct {
	client xhttp.Clientx
}

type Theme struct {
	ThemeID     string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

type ListThemesResponse struct {
	Count  int      `json:"count" yaml:"count"`
	Limit  int      `json:"limit" yaml:"limit"`
	Page   int      `json:"page" yaml:"page"`
	Total  int      `json:"total" yaml:"total"`
	Themes []*Theme `json:"themeRegistrations" yaml:"themeRegistrations"`
}

func NewThemeClient() *ThemeClient {
	return &ThemeClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *ThemeClient) ListThemes(ctx context.Context, auth *config.AuthConfig, count int, page int, limit int) (*ListThemesResponse, string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	pagination := url.Values{}
	if count > 0 {
		pagination.Add("count", fmt.Sprintf("%d", count))
	}

	if page > 0 {
		pagination.Add("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Add("limit", fmt.Sprintf("%d", limit))
	}

	params := &openapi.GetThemeRegistrationsParams{}
	if len(pagination) > 0 {
		paginationString := pagination.Encode()
		params.Pagination = &paginationString
	}

	resp, err := client.GetThemeRegistrationsWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get themes"); err != nil {
		// 	vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		// 	return nil, "", err
		// }

		vc.Logger.Errorf("unable to get the themes; responseCode=%d, responseBody=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the themes")
	}

	themes := &ListThemesResponse{}
	if err = json.Unmarshal(resp.Body, themes); err != nil {
		vc.Logger.Errorf("unable to unmarshal the themes response; body=%s, err=%s", string(resp.Body), err.Error())
		return nil, "", fmt.Errorf("unable to get the themes")
	}

	return themes, "", nil
}

func (c *ThemeClient) GetTheme(ctx context.Context, auth *config.AuthConfig, themeID string, customizedOnly bool) ([]byte, string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	params := &openapi.DownloadThemeTemplatesParams{}
	params.CustomizedOnly = &customizedOnly
	resp, err := client.DownloadThemeTemplatesWithResponse(ctx, themeID, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		req.Header.Set("Accept", "application/octet-stream")
		return nil
	})
	// response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to get the theme"); err != nil {
		// 	vc.Logger.Errorf("unable to get the theme with ID %s; err=%s", themeID, err.Error())
		// 	return nil, "", err
		// }

		vc.Logger.Errorf("unable to get the theme with ID %s; responseCode=%d, responseBody=%s", themeID, resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the theme")
	}
	return resp.Body, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *ThemeClient) GetFile(ctx context.Context, auth *config.AuthConfig, themeID string, path string) ([]byte, string, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s/%s", auth.Tenant, apiThemes, themeID, path))

	headers := http.Header{
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get the file"); err != nil {
			vc.Logger.Errorf("unable to get the theme with ID %s and path %s; err=%s", themeID, path, err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the theme with ID %s and path %s; responseCode=%d, responseBody=%s", themeID, path, response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the file")
	}

	return response.Body, u.String(), nil
}

func (c *ThemeClient) UpdateFile(ctx context.Context, auth *config.AuthConfig, themeID string, path string, data []byte) error {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s/%s", auth.Tenant, apiThemes, themeID, path))

	headers := http.Header{
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.PutMultipart(ctx, u, headers, map[string][]byte{
		"file": data,
	}, nil)
	if err != nil {
		vc.Logger.Errorf("unable to update the file; err=%s", err.Error())
		return err
	}

	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, response, "unable to update the file"); err != nil {
			vc.Logger.Errorf("unable to update the theme with ID %s and path %s; err=%s", themeID, path, err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the theme with ID %s and path %s; responseCode=%d, responseBody=%s", themeID, path, response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to update the file")
	}

	return nil
}

func (c *ThemeClient) UpdateTheme(ctx context.Context, auth *config.AuthConfig, themeID string, data []byte, metadata map[string]interface{}) error {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiThemes, themeID))

	headers := http.Header{
		"Authorization": []string{"Bearer " + auth.Token},
	}

	fields := map[string]string{}
	if len(metadata) > 0 {
		if configBytes, err := json.Marshal(metadata); err == nil {
			fields["configuration"] = string(configBytes)
		}
	}

	response, err := c.client.PutMultipart(ctx, u, headers, map[string][]byte{
		"files": data,
	}, fields)
	if err != nil {
		vc.Logger.Errorf("unable to update the theme; err=%s", err.Error())
		return err
	}

	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, response, "unable to update the theme"); err != nil {
			vc.Logger.Errorf("unable to update the theme with ID %s; err=%s", themeID, err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the theme with ID %s; responseCode=%d, responseBody=%s", themeID, response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to update the theme")
	}

	return nil
}
