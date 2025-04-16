package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-verify/verifyctl/pkg/config"
	"github.com/ibm-verify/verifyctl/pkg/module"
	xhttp "github.com/ibm-verify/verifyctl/pkg/util/http"
)

const (
	apiAccesspolicies = "v5.0/policyvault/accesspolicy"
)

// Root structure
type PolicyListResponse struct {
	Total    int      `json:"total" yaml:"total"`
	Count    int      `json:"count" yaml:"count"`
	Limit    int      `json:"limit" yaml:"limit"`
	Page     int      `json:"page" yaml:"page"`
	Policies []Policy `json:"policies" yaml:"policies"`
}

// Policy structure
type Policy struct {
	ID                    int              `json:"id" yaml:"id"`
	Name                  string           `json:"name" yaml:"name"`
	Description           string           `json:"description" yaml:"description"`
	Rules                 []Rule           `json:"rules" yaml:"rules"`
	Meta                  AccesspolicyMeta `json:"meta" yaml:"meta"`
	Validations           Validations      `json:"validations" yaml:"validations"`
	RequiredSubscriptions []string         `json:"requiredSubscriptions" yaml:"requiredSubscriptions"`
}

// Rule structure
type Rule struct {
	ID          string      `json:"id,omitempty" yaml:"id,omitempty"`
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description" yaml:"description"`
	AlwaysRun   bool        `json:"alwaysRun" yaml:"alwaysRun"`
	FirstFactor bool        `json:"firstFactor" yaml:"firstFactor"`
	Conditions  []Condition `json:"conditions" yaml:"conditions"`
	Result      Result      `json:"result" yaml:"result"`
}

// Condition represents a policy condition
type Condition struct {
	Type       string       `json:"type" yaml:"type"`
	Values     []string     `json:"values,omitempty" yaml:"values,omitempty"`
	Enabled    *bool        `json:"enabled,omitempty" yaml:"enabled,omitempty"`       // Nullable boolean
	Opcode     *string      `json:"opCode,omitempty" yaml:"opCode,omitempty"`         // Nullable string
	Attributes []Attributes `json:"attributes,omitempty" yaml:"attributes,omitempty"` // Nested attributes
}

// Attribute represents an attribute within a condition
type Attributes struct {
	Name   string   `json:"name" yaml:"name"`
	Opcode string   `json:"opCode" yaml:"opCode"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`
}

// Result structure
type Result struct {
	Action            string             `json:"action" yaml:"action"`
	ServerSideActions []ServerSideAction `json:"serverSideActions" yaml:"serverSideActions"`
	AuthnMethods      []string           `json:"authnMethods" yaml:"authnMethods"`
}

// ServerSideAction structure
type ServerSideAction struct {
	ActionID string `json:"actionId" yaml:"actionId"`
	Version  string `json:"version" yaml:"version"`
}

// Meta structure
type AccesspolicyMeta struct {
	State               string   `json:"state" yaml:"state"`
	Schema              string   `json:"schema" yaml:"schema"`
	Revision            int      `json:"revision" yaml:"revision"`
	Label               string   `json:"label" yaml:"label"`
	Predefined          bool     `json:"predefined" yaml:"predefined"`
	Created             int64    `json:"created" yaml:"created"`
	CreatedBy           string   `json:"createdBy" yaml:"createdBy"`
	LastActive          int64    `json:"lastActive" yaml:"lastActive"`
	Modified            int64    `json:"modified" yaml:"modified"`
	ModifiedBy          string   `json:"modifiedBy" yaml:"modifiedBy"`
	Scope               []string `json:"scope" yaml:"scope"`
	EnforcementType     string   `json:"enforcementType" yaml:"enforcementType"`
	ReferencedBy        []string `json:"referencedBy,omitempty" yaml:"referencedBy,omitempty"`
	References          []string `json:"references,omitempty" yaml:"references,omitempty"`
	TenantDefaultPolicy bool     `json:"tenantDefaultPolicy" yaml:"tenantDefaultPolicy"`
}

// Validations structure
type Validations struct {
	SubscriptionsNeeded []string `json:"subscriptionsNeeded" yaml:"subscriptionsNeeded"`
}

type PolicyClient struct {
	client xhttp.Clientx
}

func NewAccesspolicyClient() *PolicyClient {
	return &PolicyClient{
		client: xhttp.NewDefaultClient(),
	}
}

func (c *PolicyClient) CreateAccesspolicy(ctx context.Context, auth *config.AuthConfig, accesspolicy *Policy) (string, error) {
	vc := config.GetVerifyContext(ctx)
	defaultErr := fmt.Errorf("unable to create accesspolicy.")
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiAccesspolicies))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(accesspolicy)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal accesspolicy data; err=%v", err)
		return "", defaultErr
	}
	response, err := c.client.Post(ctx, u, headers, b)

	if err != nil {
		vc.Logger.Errorf("Unable to create accesspolicy; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode != http.StatusCreated {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to create accesspolicy"); err != nil {
			vc.Logger.Errorf("unable to create the accesspolicy; err=%s", err.Error())
			return "", fmt.Errorf("unable to create the accesspolicy; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the accesspolicy; code=%d, body=%s", response.StatusCode, string(response.Body))
		return "", fmt.Errorf("unable to create the accesspolicy; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(response.Body, &m); err != nil {
		return "", fmt.Errorf("Failed to parse response: %v", err)
	}

	id, ok := m["id"].(float64)
	if !ok {
		return "", fmt.Errorf("Failed to parse 'id' as float64")
	}

	return fmt.Sprintf("https://%s/%s/%d", auth.Tenant, apiAccesspolicies, int(id)), nil
}

func (c *PolicyClient) GetAccesspolicy(ctx context.Context, auth *config.AuthConfig, accesspolicyName string) (*Policy, string, error) {
	vc := config.GetVerifyContext(ctx)
	id, err := c.getAccesspolicyId(ctx, auth, accesspolicyName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAccesspolicies, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to get the Access Policy; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get Access Policy"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policy; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Access Policy; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Access Policy")
	}

	Accesspolicy := &Policy{}
	if err = json.Unmarshal(response.Body, Accesspolicy); err != nil {
		return nil, "", fmt.Errorf("unable to get the Access Policy")
	}

	return Accesspolicy, u.String(), nil
}

func (c *PolicyClient) GetAccesspolicies(ctx context.Context, auth *config.AuthConfig) (
	*PolicyListResponse, string, error) {

	vc := config.GetVerifyContext(ctx)
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiAccesspolicies))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	response, err := c.client.Get(ctx, u, headers)

	if err != nil {
		vc.Logger.Errorf("unable to get the Access Policies; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get Access Policies"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policies; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Access Policies; code=%d, body=%s", response.StatusCode, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Access Policies")
	}

	AccesspoliciesResponse := &PolicyListResponse{}
	if err = json.Unmarshal(response.Body, &AccesspoliciesResponse); err != nil {
		vc.Logger.Errorf("unable to get the Accesspolicies; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Accesspolicies")
	}

	return AccesspoliciesResponse, u.String(), nil
}

func (c *PolicyClient) DeleteAccesspolicy(ctx context.Context, auth *config.AuthConfig, name string) error {
	vc := config.GetVerifyContext(ctx)

	id, err := c.getAccesspolicyId(ctx, auth, name)
	if err != nil {
		vc.Logger.Errorf("unable to get the accesspolicy ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the accesspolicy ID; err=%s", err.Error())
	}

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}
	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAccesspolicies, id))

	response, err := c.client.Delete(ctx, u, headers)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Access Policy; err=%s", err.Error())
		return fmt.Errorf("unable to delete the Access Policy; err=%s", err.Error())
	}

	if response.StatusCode != http.StatusNoContent {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to delete Access Policy"); err != nil {
			vc.Logger.Errorf("unable to delete the Access Policy; err=%s", err.Error())
			return fmt.Errorf("unable to delete the Access Policy; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the Access Policy; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("unable to delete the Access Policy; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *PolicyClient) UpdateAccesspolicy(ctx context.Context, auth *config.AuthConfig, accesspolicy *Policy) error {
	vc := config.GetVerifyContext(ctx)

	id, err := c.getAccesspolicyId(ctx, auth, accesspolicy.Name)
	if err != nil {
		vc.Logger.Errorf("unable to get the accesspolicy ID; err=%s", err.Error())
		return fmt.Errorf("unable to get the accesspolicy ID; err=%s", err.Error())
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", auth.Tenant, apiAccesspolicies, id))
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	b, err := json.Marshal(accesspolicy)

	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return fmt.Errorf("unable to marshal the patch request; err=%v", err)
	}

	response, err := c.client.Put(ctx, u, headers, b)

	if err != nil {
		vc.Logger.Errorf("unable to update accesspolicy; err=%v", err)
		return fmt.Errorf("unable to update accesspolicy; err=%v", err)
	}
	if response.StatusCode != http.StatusCreated {
		vc.Logger.Errorf("failed to update accesspolicy; code=%d, body=%s", response.StatusCode, string(response.Body))
		return fmt.Errorf("failed to update accesspolicy ; code=%d, body=%s", response.StatusCode, string(response.Body))
	}

	return nil
}

func (c *PolicyClient) getAccesspolicyId(ctx context.Context, auth *config.AuthConfig, name string) (string, error) {
	vc := config.GetVerifyContext(ctx)
	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + auth.Token},
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", auth.Tenant, apiAccesspolicies))
	q := u.Query()
	q.Set("search", fmt.Sprintf(`name = "%s"`, name))

	u.RawQuery = q.Encode()
	response, _ := c.client.Get(ctx, u, headers)

	if response.StatusCode != http.StatusOK {
		if err := module.HandleCommonErrorsX(ctx, response, "unable to get Access Policy"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policy with accesspolicyName %s; err=%s", name, err.Error())
			return "", fmt.Errorf("unable to get the Access Policy with accesspolicyName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	policies, ok := data["policies"].([]interface{})
	if !ok || len(policies) == 0 {
		return "", fmt.Errorf("no accesspolicy found with accesspolicyName %s", name)
	}

	firstResource, ok := policies[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid resource format")
	}

	// Extract "id" field
	id, ok := firstResource["id"].(float64)
	if !ok {
		return "", fmt.Errorf("ID not found or invalid type")
	}
	return fmt.Sprintf("%d", int(id)), nil
}
