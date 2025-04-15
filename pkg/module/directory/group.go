package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/module"
	"github.com/ibm-verify/verifyctl/pkg/module/openapi"
)

type GroupClient struct{}

type GroupPatchRequest struct {
	GroupName        string            `json:"displayName" yaml:"displayName"`
	SCIMPatchRequest openapi.PatchBody `json:"scimPatch" yaml:"scimPatch"`
}

type Group = openapi.GroupResponseV2
type GroupListResponse = openapi.GetGroupsResponseV2
type GroupPatchOperation = openapi.PatchOperation0

func NewGroupClient() *GroupClient {
	return &GroupClient{}
}

func (c *GroupClient) GetGroup(ctx context.Context, auth *config.AuthConfig, groupName string) (*Group, string, error) {
	vc := config.GetVerifyContext(ctx)
	id, err := c.getGroupId(ctx, auth, groupName)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	resp, err := client.GetGroupWithResponse(ctx, id, &openapi.GetGroupParams{}, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to get the Group; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Group"); err != nil {
			vc.Logger.Errorf("unable to get the Group; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Group")
	}

	Group := &Group{}
	if err = json.Unmarshal(resp.Body, Group); err != nil {
		return nil, "", fmt.Errorf("unable to get the Group")
	}

	return Group, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *GroupClient) GetGroups(ctx context.Context, auth *config.AuthConfig, sort string, count string) (*GroupListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))

	params := &openapi.GetGroupsParams{}
	if len(sort) > 0 {
		params.SortBy = &sort
	}
	if len(count) > 0 {
		params.Count = &count
	}

	resp, err := client.GetGroupsWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("unable to get the Groups; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Groups"); err != nil {
			vc.Logger.Errorf("unable to get the Groups; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Groups; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Groups")
	}

	GroupsResponse := &GroupListResponse{}
	if err = json.Unmarshal(resp.Body, &GroupsResponse); err != nil {
		vc.Logger.Errorf("unable to get the Groups; err=%s, body=%s", err, string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the Groups")
	}

	return GroupsResponse, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *GroupClient) CreateGroup(ctx context.Context, auth *config.AuthConfig, group *Group) (string, error) {
	vc := config.GetVerifyContext(ctx)
	userClient := NewUserClient()
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))

	for i, m := range *group.Members {
		// Get the username from the member's Value field.
		username := m.Value
		// Retrieve the actual user ID using the provided function.
		userID, err := userClient.getUserId(ctx, auth, username)
		if err != nil {
			vc.Logger.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
			return "", fmt.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
		}

		// Update the member's Value with the obtained user ID.
		(*group.Members)[i].Value = userID
	}

	body, err := json.Marshal(group)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal group data; err=%v", err)
		return "", err
	}

	params := &openapi.CreateGroupParams{}
	resp, err := client.CreateGroupWithBodyWithResponse(ctx, params, "application/scim+json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("groupshouldnotneedtoresetpassword", "false")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if err != nil {
		vc.Logger.Errorf("Unable to create group; err=%v", err)
		return "", err
	}

	if resp.StatusCode() != http.StatusCreated {
		vc.Logger.Errorf("Failed to create group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", fmt.Errorf("failed to create group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		return "", fmt.Errorf("failed to parse response")
	}

	id := m["id"].(string)
	return fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id), nil
}

func (c *GroupClient) DeleteGroup(ctx context.Context, auth *config.AuthConfig, groupName string) error {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	id, err := c.getGroupId(ctx, auth, groupName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the group ID; err=%s", err.Error())
	}

	resp, err := client.DeleteGroupWithResponse(ctx, id, &openapi.DeleteGroupParams{}, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to delete the Group; err=%s", err.Error())
		return fmt.Errorf("unable to delete the Group; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to delete Group"); err != nil {
			vc.Logger.Errorf("unable to delete the Group; err=%s", err.Error())
			return fmt.Errorf("unable to delete the Group; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the Group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return fmt.Errorf("unable to delete the Group")
	}

	return nil
}

func (c *GroupClient) UpdateGroup(ctx context.Context, auth *config.AuthConfig, groupName string, operations []GroupPatchOperation) error {
	vc := config.GetVerifyContext(ctx)
	userClient := NewUserClient()
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	groupID, err := c.getGroupId(ctx, auth, groupName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the group ID; err=%s", err.Error())
	}

	for i, op := range operations {
		if op.Op == "add" && op.Path == "members" {
			if values, ok := (*op.Value).([]interface{}); ok {
				for j, v := range values {
					if member, ok := v.(map[string]interface{}); ok {
						if username, exists := member["value"].(string); exists {
							userID, err := userClient.getUserId(ctx, auth, username)
							if err != nil {
								vc.Logger.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
								return fmt.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
							}
							(*operations[i].Value).([]interface{})[j].(map[string]interface{})["value"] = userID
						}
					}
				}
			}
		} else if op.Op == "remove" {
			username := extractUsernameFromPath(op.Path)
			if username != "" {
				userID, err := userClient.getUserId(ctx, auth, username)
				if err != nil {
					vc.Logger.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
					return fmt.Errorf("unable to get user ID for username %s; err=%s", username, err.Error())
				}
				operations[i].Path = fmt.Sprintf("members[value eq \"%s\"]", userID)
			}
		}
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
	resp, err := client.PatchGroupWithBodyWithResponse(ctx, groupID, &openapi.PatchGroupParams{}, "application/scim+json", bytes.NewBuffer(body), func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to update group; err=%v", err)
		return fmt.Errorf("unable to update group; err=%v", err)
	}
	if resp.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update group; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return fmt.Errorf("failed to update group ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *GroupClient) getGroupId(ctx context.Context, auth *config.AuthConfig, name string) (string, error) {
	vc := config.GetVerifyContext(ctx)
	client, _ := openapi.NewClientWithResponses(fmt.Sprintf("https://%s", auth.Tenant))
	filter := fmt.Sprintf(`displayName eq "%s"`, name)
	params := &openapi.GetGroupsParams{
		Filter: &filter,
	}
	resp, _ := client.GetGroupsWithResponse(ctx, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Accept", "application/scim+json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.Token))
		return nil
	})

	if resp.StatusCode() != http.StatusOK {
		if err := module.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Group"); err != nil {
			vc.Logger.Errorf("unable to get the Group with groupName %s; err=%s", name, err.Error())
			return "", fmt.Errorf("unable to get the Group with groupName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	resources, ok := data["Resources"].([]interface{})
	if !ok || len(resources) == 0 {
		return "", fmt.Errorf("no group found with group name %s", name)
	}

	firstResource, ok := resources[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid resource format")
	}

	id, ok := firstResource["id"].(string)
	if !ok {
		return "", fmt.Errorf("ID not found or invalid type")
	}

	return id, nil
}

func extractUsernameFromPath(path string) string {
	re := regexp.MustCompile(`value eq "?([^"]+)"?`)
	match := re.FindStringSubmatch(path)

	if len(match) > 1 {
		return match[1]
	}
	return ""
}
