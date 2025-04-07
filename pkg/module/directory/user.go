package directory

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
	apiUsers = "v2.0/Users"
)

type UserClient struct {
	client xhttp.Clientx
}

type UserListResponse struct {
	TotalResults int      `json:"totalResults" yaml:"totalResults"`
	Schemas      []string `json:"schemas" yaml:"schemas"`
	Users        []User   `json:"Resources" yaml:"Resources"`
}

type User struct {
	Id                string          `json:"id,omitempty" yaml:"id,omitempty"`
	UserName          string          `json:"userName,omitempty" yaml:"userName,omitempty"`
	ExternalID        string          `json:"externalId,omitempty" yaml:"externalId,omitempty"`
	Title             string          `json:"title,omitempty" yaml:"title,omitempty"`
	Password          string          `json:"password,omitempty" yaml:"password,omitempty"`
	DisplayName       string          `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	PreferredLanguage string          `json:"preferredLanguage,omitempty" yaml:"preferredLanguage,omitempty"`
	Active            bool            `json:"active" yaml:"active"`
	Emails            []Email         `json:"emails,omitempty" yaml:"emails,omitempty"`
	Addresses         []Address       `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	PhoneNumbers      []PhoneNumber   `json:"phoneNumbers,omitempty" yaml:"phoneNumbers,omitempty"`
	Meta              Meta            `json:"meta,omitempty" yaml:"meta,omitempty"`
	Name              Name            `json:"name" yaml:"name"`
	Schemas           []string        `json:"schemas" yaml:"schemas"`
	IBMUserExtension  IBMUser         `json:"urn:ietf:params:scim:schemas:extension:ibm:2.0:User,omitempty" yaml:"urn:ietf:params:scim:schemas:extension:ibm:2.0:User,omitempty"`
	EnterpriseUser    *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty" yaml:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Notification      Notification    `json:"urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification,omitempty" yaml:"urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification,omitempty"`
	Groups            []Group         `json:"groups,omitempty" yaml:"groups,omitempty"`
}

type Name struct {
	Formatted  string `json:"formatted,omitempty" yaml:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty" yaml:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty" yaml:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty" yaml:"middleName,omitempty"`
}

type Email struct {
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
}

type Address struct {
	StreetAddress string `json:"streetAddress,omitempty" yaml:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty" yaml:"locality,omitempty"`
	Region        string `json:"region,omitempty" yaml:"region,omitempty"`
	Country       string `json:"country,omitempty" yaml:"country,omitempty"`
	PostalCode    string `json:"postalCode,omitempty" yaml:"postalCode,omitempty"`
	Type          string `json:"type,omitempty" yaml:"type,omitempty"`
	Formatted     string `json:"formatted,omitempty" yaml:"formatted,omitempty"`
	Primary       bool   `json:"primary,omitempty" yaml:"primary,omitempty"`
}

type PhoneNumber struct {
	Type  string `json:"type,omitempty" yaml:"type,omitempty"`
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

type Meta struct {
	Created      string `json:"created,omitempty" yaml:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty" yaml:"lastModified,omitempty"`
	ResourceType string `json:"resourceType,omitempty" yaml:"resourceType,omitempty"`
}

type IBMUser struct {
	LastLoginType    string            `json:"lastLoginType,omitempty" yaml:"lastLoginType,omitempty"`
	Realm            string            `json:"realm,omitempty" yaml:"realm,omitempty"`
	UserCategory     string            `json:"userCategory,omitempty" yaml:"userCategory,omitempty"`
	EmailVerified    string            `json:"emailVerified,omitempty" yaml:"emailVerified,omitempty"`
	Delegate         string            `json:"delegate,omitempty" yaml:"delegate,omitempty"`
	CustomAttributes []CustomAttribute `json:"customAttributes,omitempty" yaml:"customAttributes,omitempty"`
	AccountExpires   string            `json:"accountExpires,omitempty" yaml:"accountExpires,omitempty"`
}

type CustomAttribute struct {
	Name   string   `json:"name,omitempty" yaml:"name,omitempty"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`
}

type EnterpriseUser struct {
	Department     string  `json:"department,omitempty" yaml:"department,omitempty"`
	EmployeeNumber string  `json:"employeeNumber,omitempty" yaml:"employeeNumber,omitempty"`
	Manager        Manager `json:"manager,omitempty" yaml:"manager,omitempty"`
}

type Manager struct {
	Value       string `json:"value,omitempty" yaml:"value,omitempty"`
	Ref         string `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	DisplayName string `json:"displayName,omitempty" yaml:"displayName,omitempty"`
}

type Notification struct {
	NotifyType     string `json:"notifyType" yaml:"notifyType"`
	NotifyPassword bool   `json:"notifyPassword" yaml:"notifyPassword"`
	NotifyManager  bool   `json:"notifyManager" yaml:"notifyManager"`
}

type UserGroup struct {
	DisplayName string `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	ID          string `json:"id,omitempty" yaml:"id,omitempty"`
	Ref         string `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Value       string `json:"value,omitempty" yaml:"value,omitempty"`
}

type UserPatchRequest struct {
	UserName         string               `json:"userName" yaml:"userName"`
	SCIMPatchRequest UserSCIMPatchRequest `json:"scimPatch" yaml:"scimPatch"`
}

type UserSCIMPatchRequest struct {
	Schemas    []string          `json:"schemas" yaml:"schemas"`
	Operations []UserSCIMOpEntry `json:"Operations" yaml:"Operations"`
}

type UserSCIMOpEntry struct {
	Op    string      `json:"op" yaml:"op"`
	Path  string      `json:"path,omitempty" yaml:"path,omitempty"`
	Value interface{} `json:"value,omitempty" yaml:"value,omitempty"`
}

func NewUserClient() *UserClient {
	return &UserClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *UserClient) CreateUser(ctx context.Context, auth *config.AuthConfig, user *User) (string, error) {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to create user.")
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiUsers))
	headers := http.Header{
		"Accept":                           []string{"application/scim+json"},
		"Content-Type":                     []string{"application/scim+json"},
		"usershouldnotneedtoresetpassword": []string{"false"},
		"Authorization":                    []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(user)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal user data; err=%v", err)
		return "", defaultErr
	}

	response, err := c.client.Post(ctx, u, headers, b)

	if err != nil {
		vc.Logger.Errorf("Unable to create user; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode != http.StatusCreated {
		if err := module.HandleCommonErrors(ctx, response, "unable to create user"); err != nil {
			vc.Logger.Errorf("unable to create the user; err=%s", err.Error())
			return "", fmt.Errorf("unable to create the user; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the user; code=%d, body=%s", response.StatusCode, string(response.Body))
		return "", fmt.Errorf("unable to create the user; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(response.Body, &m); err != nil {
		return "", fmt.Errorf("Failed to parse response")
	}

	id := m["id"].(string)
	return fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiUsers, id), nil
}

func (c *UserClient) GetUser(ctx context.Context, auth *config.AuthConfig, userName string) (*openapi.UserResponseV2, string, error) {
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

	User := &openapi.UserResponseV2{}
	if err = json.Unmarshal(resp.Body, User); err != nil {
		return nil, "", fmt.Errorf("unable to get the User")
	}

	return User, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *UserClient) GetUsers(ctx context.Context, auth *config.AuthConfig, sort string, count string) (
	*UserListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiUsers))
	headers := http.Header{
		"Accept":        []string{"application/scim+json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	q := u.Query()

	if len(sort) > 0 {
		q.Set("sortBy", sort)
	}

	if len(count) > 0 {
		q.Set("count", count)
	}

	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}

	response, err := c.client.Get(ctx, u, headers)

	if err != nil {
		vc.Logger.Errorf("unable to get the Users; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get Users"); err != nil {
			vc.Logger.Errorf("unable to get the Users; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Users; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Users")
	}

	UsersResponse := &UserListResponse{}
	if err = json.Unmarshal(response.Body, &UsersResponse); err != nil {
		vc.Logger.Errorf("unable to get the Users; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Users")
	}

	return UsersResponse, u.String(), nil
}

func (c *UserClient) DeleteUser(ctx context.Context, auth *config.AuthConfig, name string) error {
	vc := config.GetVerifyContext(ctx)

	id, err := c.getUserId(ctx, auth, name)
	if err != nil {
		vc.Logger.Errorf("unable to get the user ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the user ID; err=%s", err.Error())
	}

	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiUsers, id))

	response, err := c.client.Delete(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to delete the User; err=%s", err.Error())
		return fmt.Errorf("unable to delete the User; err=%s", err.Error())
	}

	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, response, "unable to delete User"); err != nil {
			vc.Logger.Errorf("unable to delete the User; err=%s", err.Error())
			return fmt.Errorf("unable to delete the User; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the User; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to delete the User; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *UserClient) UpdateUser(ctx context.Context, auth *config.AuthConfig, userName string, operations []UserSCIMOpEntry) error {
	vc := config.GetVerifyContext(ctx)

	id, err := c.getUserId(ctx, auth, userName)
	if err != nil {
		vc.Logger.Errorf("unable to get the user ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the user ID; err=%s", err.Error())
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiUsers, id))
	headers := http.Header{
		"Accept":                           []string{"application/scim+json"},
		"Content-Type":                     []string{"application/scim+json"},
		"usershouldnotneedtoresetpassword": []string{"false"},
		"Authorization":                    []string{"Bearer " + auth.Token},
	}

	patchRequest := UserSCIMPatchRequest{
		Schemas:    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: operations,
	}

	b, err := json.Marshal(patchRequest)

	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return fmt.Errorf("unable to marshal the patch request; err=%v", err)
	}

	response, err := c.client.Patch(ctx, u, headers, b)

	if err != nil {
		vc.Logger.Errorf("unable to update user; err=%v", err)
		return fmt.Errorf("unable to update user; err=%v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		vc.Logger.Errorf("failed to update user; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("failed to update user ; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *UserClient) getUserId(ctx context.Context, auth *config.AuthConfig, name string) (string, error) {
	vc := config.GetVerifyContext(ctx)
	headers := http.Header{
		"Accept":        []string{"application/scim+json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiUsers))
	q := u.Query()
	q.Set("filter", fmt.Sprintf(`userName eq "%s"`, name))
	u.RawQuery = q.Encode()

	response, _ := c.client.Get(ctx, u, headers)

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, response, "unable to get User"); err != nil {
			vc.Logger.Errorf("unable to get the User with userName %s; err=%s", name, err.Error())
			return "", fmt.Errorf("unable to get the User with userName %s; err=%s", name, err.Error())
		}
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
