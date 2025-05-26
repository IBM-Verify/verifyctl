package resource

import "github.com/ibm-verify/verify-sdk-go/pkg/config/security"

func CreateAPIClientBoilerplate(apiClientBoilerplate *security.APIClientConfig) {
	dummyBool := true
	dummyStr := " "
	dummyMap := map[string]interface{}{" ": " "}
	dummyIPFilterOp := security.APIClientConfigIPFilterOp(" ")
	apiClientBoilerplate.Entitlements = []string{" "}
	apiClientBoilerplate.Enabled = &dummyBool
	apiClientBoilerplate.Description = &dummyStr
	apiClientBoilerplate.IPFilterOp = &dummyIPFilterOp
	apiClientBoilerplate.IPFilters = &[]string{" "}
	apiClientBoilerplate.JwkURI = &dummyStr
	apiClientBoilerplate.AdditionalProperties = &dummyMap
	apiClientBoilerplate.OverrideSettings = &security.APIClientOverrideSettings{
		RestrictScopes: &dummyBool,
		Scopes: &[]security.APIClientScopes{
			{Name: &dummyStr, Description: &dummyStr},
		},
	}
	apiClientBoilerplate.AdditionalConfig = &security.APIClientAdditionalConfig{
		ClientAuthMethod:                       &dummyStr,
		ValidateClientAssertionJti:             &dummyBool,
		AllowedClientAssertionVerificationKeys: &[]string{" "},
	}
}
