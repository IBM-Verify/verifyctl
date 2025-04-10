package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
)

type UserClient struct {
	client xhttp.Clientx
}

type User = openapi.UserResponseV2
type UserListResponse = openapi.GetUsersResponseV2
type UserPatchOperation = openapi.PatchOperation0

type UserPatchRequest struct {
	UserName         string            `json:"userName" yaml:"userName"`
	SCIMPatchRequest openapi.PatchBody `json:"scimPatch" yaml:"scimPatch"`
}

func NewUserClient() *UserClient {
	return &UserClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *UserClient) CreateUser(ctx context.Context, auth *config.AuthConfig, user *User) (string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	defaultErr := fmt.Errorf("unable to create user")
	body, err := json.Marshal(user)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal user data; err=%v", err)
		return "", defaultErr
	}
	var usershouldnotneedtoresetpassword openapi.CreateUserParamsUsershouldnotneedtoresetpassword = "false"
	params := &openapi.CreateUserParams{
		Usershouldnotneedtoresetpassword: &usershouldnotneedtoresetpassword,
	}
	resp, err := client.CreateUserWithBodyWithResponse(ctx, params, "application/scim+json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("Unable to create user; err=%v", err)
		return "", defaultErr
	}

	if resp.StatusCode() != http.StatusCreated {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to create user"); err != nil {
		// 	vc.Logger.Errorf("unable to create the user; err=%s", err.Error())
		// 	return "", fmt.Errorf("unable to create the user; err=%s", err.Error())
		// }

		vc.Logger.Errorf("unable to create the user; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", fmt.Errorf("unable to create the user; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		return "", fmt.Errorf("failed to parse response")
	}

	id := m["id"].(string)
	return fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id), nil
}

func (c *UserClient) GetUser(ctx context.Context, auth *config.AuthConfig, userName string) (*User, string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	id, err := c.getUserId(ctx, auth, userName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}
	params := &openapi.GetUser0Params{}
	resp, err := client.GetUser0WithResponse(ctx, id, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Accept", "application/scim+json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to get the User; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to get User"); err != nil {
		// 	vc.Logger.Errorf("unable to get the User; err=%s", err.Error())
		// 	return nil, "", err
		// }

		vc.Logger.Errorf("unable to get the User; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the User")
	}

	User := &User{}
	if err = json.Unmarshal(resp.Body, User); err != nil {
		return nil, "", fmt.Errorf("unable to get the User")
	}

	return User, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *UserClient) GetUsers(ctx context.Context, auth *config.AuthConfig, sort string, count string) (*UserListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))

	params := &openapi.GetUsersParams{}
	if len(sort) > 0 {
		params.SortBy = &sort
	}
	if len(count) > 0 {
		params.Count = &count
	}

	resp, err := client.GetUsersWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", "Bearer "+auth.Token)
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to get the Users; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, resp, "unable to get Users"); err != nil {
		// 	vc.Logger.Errorf("unable to get the Users; err=%s", err.Error())
		// 	return nil, "", err
		// }

		vc.Logger.Errorf("unable to get the Users; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Users")
	}

	UsersResponse := &UserListResponse{}
	if err = json.Unmarshal(resp.Body, &UsersResponse); err != nil {
		vc.Logger.Errorf("unable to get the Users; err=%s, body=%s", err, string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Users")
	}

	return UsersResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *UserClient) DeleteUser(ctx context.Context, auth *config.AuthConfig, name string) error {
	vc := config.GetVerifyContext(ctx)
	id, err := c.getUserId(ctx, auth, name)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	if err != nil {
		vc.Logger.Errorf("unable to get the user ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the user ID; err=%s", err.Error())
	}

	resp, err := client.DeleteUser0WithResponse(ctx, id, &openapi.DeleteUser0Params{}, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to delete the User; err=%s", err.Error())
		return fmt.Errorf("unable to delete the User; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		// if err := module.HandleCommonErrors(ctx, response, "unable to delete User"); err != nil {
		// 	vc.Logger.Errorf("unable to delete the User; err=%s", err.Error())
		// 	return fmt.Errorf("unable to delete the User; err=%s", err.Error())
		// }

		vc.Logger.Errorf("unable to delete the User; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return fmt.Errorf("unable to delete the User; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *UserClient) UpdateUser(ctx context.Context, auth *config.AuthConfig, userName string, operations []UserPatchOperation) error {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	id, err := c.getUserId(ctx, auth, userName)
	if err != nil {
		vc.Logger.Errorf("unable to get the user ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the user ID; err=%s", err.Error())
	}

	patchRequest := openapi.PatchBody{
		Schemas:    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: operations,
	}

	body, err := json.Marshal(patchRequest)

	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return fmt.Errorf("unable to marshal the patch request; err=%v", err)
	}
	var usershouldnotneedtoresetpassword openapi.PatchUserParamsUsershouldnotneedtoresetpassword = "false"
	params := &openapi.PatchUserParams{
		Usershouldnotneedtoresetpassword: &usershouldnotneedtoresetpassword,
	}
	resp, err := client.PatchUserWithBodyWithResponse(ctx, id, params, "application/scim+json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to update user; err=%v", err)
		return fmt.Errorf("unable to update user; err=%v", err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update user; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return fmt.Errorf("failed to update user ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *UserClient) getUserId(ctx context.Context, auth *config.AuthConfig, name string) (string, error) {
	// vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	filter := fmt.Sprintf(`userName eq "%s"`, name)
	params := &openapi.GetUsersParams{
		Filter: &filter,
	}
	response, _ := client.GetUsersWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", "Bearer "+auth.Token)
		return nil
	})

	if response.StatusCode() != http.StatusOK {
		// if err := module.HandleCommonErrors(ctx, response, "unable to get User"); err != nil {
		// 	vc.Logger.Errorf("unable to get the User with userName %s; err=%s", name, err.Error())
		// 	return "", fmt.Errorf("unable to get the User with userName %s; err=%s", name, err.Error())
		// }
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	resources, ok := data["Resources"].([]interface{})
	if !ok || len(resources) == 0 {
		return "", fmt.Errorf("no user found with userName %s", name)
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
