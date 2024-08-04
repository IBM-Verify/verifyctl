package branding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
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

func (c *ThemeClient) ListThemes(ctx context.Context, auth *config.AuthConfig, count int, page int, limit int) (*ListThemesResponse, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiThemes))
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

	if len(pagination) > 0 {
		q := u.Query()
		q.Set("pagination", pagination.Encode())
		u.RawQuery = q.Encode()
	}

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get themes"); err != nil {
			vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
			return nil, err
		}

		vc.Logger.Errorf("unable to get the themes; responseCode=%d, responseBody=%s", response.StatusCode, string(response.Body))
		return nil, fmt.Errorf("unable to get the themes")
	}

	themes := &ListThemesResponse{}
	if err = json.Unmarshal(response.Body, themes); err != nil {
		vc.Logger.Errorf("unable to unmarshal the themes response; body=%s, err=%s", string(response.Body), err.Error())
		return nil, fmt.Errorf("unable to get the themes")
	}

	return themes, nil
}

func (c *ThemeClient) GetTheme(ctx context.Context, auth *config.AuthConfig, themeID string, customizedOnly bool) ([]byte, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiThemes, themeID))
	q := u.Query()
	q.Set("customized_only", strconv.FormatBool(customizedOnly))
	u.RawQuery = q.Encode()

	headers := http.Header{
		"Accept":        []string{"application/octet-stream"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get the theme"); err != nil {
			vc.Logger.Errorf("unable to get the theme with ID %s; err=%s", themeID, err.Error())
			return nil, err
		}

		vc.Logger.Errorf("unable to get the theme with ID %s; responseCode=%d, responseBody=%s", themeID, response.StatusCode, string(response.Body))
		return nil, fmt.Errorf("unable to get the theme")
	}

	return response.Body, nil
}

func (c *ThemeClient) GetFile(ctx context.Context, auth *config.AuthConfig, themeID string, path string) ([]byte, error) {
	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s/%s", auth.Tenant, apiThemes, themeID, path))

	headers := http.Header{
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get the file"); err != nil {
			vc.Logger.Errorf("unable to get the theme with ID %s and path %s; err=%s", themeID, path, err.Error())
			return nil, err
		}

		vc.Logger.Errorf("unable to get the theme with ID %s and path %s; responseCode=%d, responseBody=%s", themeID, path, response.StatusCode, string(response.Body))
		return nil, fmt.Errorf("unable to get the file")
	}

	return response.Body, nil
}
