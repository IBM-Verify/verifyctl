package resource

import (
	"github.com/ibm-verify/verify-sdk-go/pkg/config/applications"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
)

type SignInOptions struct {
	InstanceName string                   `json:"instanceName" yaml:"instanceName"`
	Properties   []map[string]interface{} `json:"properties" yaml:"properties"`
}

func CreateApplicationBoilerplate(applicationBoilerplate *applications.Application, applicationType string) {
	// setting common fields
	applicationBoilerplate.VisibleOnLaunchpad = true
	applicationBoilerplate.ApplicationState = true
	applicationBoilerplate.Description = " "
	applicationBoilerplate.TemplateID = " "
	if applicationType == "saml" {
		applicationBoilerplate.Owners = append(applicationBoilerplate.Owners, " ")
		// set target
		applicationBoilerplate.Target = map[string]bool{
			"connectedApp_SalesforceChatter":      true,
			"connectedApp_DataDotcom":             false,
			"connectedApp_SalesforceSalesCloud":   false,
			"connectedApp_SalesforceServiceCloud": false,
		}
		// set providers
		applicationBoilerplate.Providers = applications.Providers{
			SAML: applications.SAML{
				JustInTimeProvisioning: "false",
				Properties: applications.SAMLProperties{
					CompanyName:                 " ",
					GenerateUniqueID:            "false",
					ValidateAuthnRequest:        "false",
					EncryptAssertion:            "false",
					ICIReservedSubjectNameID:    " ",
					IncludeAllAttributes:        "true",
					UniqueID:                    " ",
					ProviderID:                  " ",
					AssertionConsumerServiceURL: " ",
				},
			},
			SSO: applications.SSO{
				DomainName: " ",
			},
		}
		// set provisioning
		applicationBoilerplate.Provisioning = applications.Provisioning{
			Policies: applications.ProvisioningPolicies{
				GracePeriod:  1,
				ProvPolicy:   "disabled",
				DeProvPolicy: "disabled",
				DeProvAction: "suspend",
				AdoptionPolicy: applications.AdoptionPolicy{
					MatchingAttributes: []*applications.AttributeMapping{},
					RemediationPolicy: map[string]string{
						"policy": "NONE",
					},
				},
			},
		}
	} else if applicationType == "aclc" {
		// set provisioning
		applicationBoilerplate.Provisioning = applications.Provisioning{
			Extension: applications.Extension{
				Properties: map[string]string{
					"endpointBaseUrl": "",
				},
			},
			AttributeMappings: []*applications.AttributeMapping{
				{TargetName: "userName", SourceID: "3", OutboundTracking: true},
			},
			ReverseAttributeMappings: []*applications.AttributeMapping{
				{TargetName: "userName", SourceID: "3", OutboundTracking: true},
			},
			Policies: applications.ProvisioningPolicies{
				ProvPolicy:   "automatic",
				DeProvPolicy: "automatic",
				DeProvAction: "delete",
				GracePeriod:  0,
				AdoptionPolicy: applications.AdoptionPolicy{
					MatchingAttributes: []*applications.AttributeMapping{
						{TargetName: "emails[0].value", SourceID: "3"},
					},
					RemediationPolicy: map[string]string{
						"policy": "NONE",
					},
				},
			},
			Authentication: applications.Authentication{
				Properties: map[string]string{
					"pwd_client_secret": " ",
					"client_id":         " ",
				},
			},
			SendNotifications: true,
		}
		// set Provider
		applicationBoilerplate.Providers = applications.Providers{
			SSO: applications.SSO{
				DomainName:  " ",
				UserOptions: " ",
			},
			SAML: applications.SAML{
				JustInTimeProvisioning: "false",
				Properties: applications.SAMLProperties{
					CompanyName: " ",
				},
			},
			Bookmark: applications.Bookmark{
				BookmarkURL: " ",
			},
		}
	} else if applicationType == "oidc" {
		// set providers
		applicationBoilerplate.Providers = applications.Providers{
			SSO: applications.SSO{
				UserOptions: "oidc",
			},
			SAML: applications.SAML{
				Properties: applications.SAMLProperties{
					CompanyName: " ",
					UniqueID:    " ",
				},
			},
			OIDC: applications.OIDC{
				Properties: applications.OIDCProperties{
					DoNotGenerateClientSecret: "false",
					GenerateRefreshToken:      "false",
					RenewRefreshToken:         "true",
					IDTokenEncryptAlg:         "none",
					IDTokenEncryptEnc:         "none",
					GrantTypes: applications.GrantTypes{
						AuthorizationCode: true,
						Implicit:          true,
						ClientCredentials: true,
						ROPC:              true,
						TokenExchange:     true,
						DeviceFlow:        true,
						JWTBearer:         true,
						PolicyAuth:        true,
					},
					AccessTokenExpiry:  1,
					RefreshTokenExpiry: 1,
					IDTokenSigningAlg:  "RS256",
					RedirectURIs:       []interface{}{" ", " "},
					AdditionalConfig: applications.OIDCAdditionalConfig{
						Oidcv3:                                 true,
						RequestObjectParametersOnly:            "false",
						RequestObjectSigningAlg:                "RS256",
						RequestObjectRequireExp:                "true",
						CertificateBoundAccessTokens:           "false",
						DpopBoundAccessTokens:                  "false",
						ValidateDPoPProofJti:                   "false",
						DpopProofSigningAlg:                    "RS256",
						AuthorizeRspSigningAlg:                 "RS256",
						AuthorizeRspEncryptionAlg:              "none",
						AuthorizeRspEncryptionEnc:              "none",
						ResponseTypes:                          []string{"none", "code"},
						ResponseModes:                          []string{"query", "fragment", "form_post", "query.jwt", "fragment.jwt", "form_post.jwt"},
						ClientAuthMethod:                       "default",
						RequirePushAuthorize:                   "false",
						RequestObjectMaxExpFromNbf:             1,
						ExchangeForSSOSessionOption:            "default",
						SubjectTokenTypes:                      []string{"urn:ietf:params:oauth:token-type:access_token"},
						ActorTokenTypes:                        []string{"urn:ietf:params:oauth:token-type:access_token"},
						RequestedTokenTypes:                    []string{"urn:ietf:params:oauth:token-type:access_token"},
						ActorTokenRequired:                     true,
						LogoutOption:                           "none",
						SessionRequired:                        true,
						RequestUris:                            []string{" "},
						AllowedClientAssertionVerificationKeys: []string{" ", " "},
					},
				},
				Token: applications.Token{
					AccessTokenType: "default",
					Audiences:       []interface{}{" "},
				},
				GrantProperties: applications.GrantProperties{
					GenerateDeviceFlowQRCode: "false",
				},
				RequirePKCEVerification: "true",
				ConsentAction:           "always_promt",
				ApplicationURL:          " ",
				RestrictEntitlements:    true,
			},
		}

	} else if applicationType == "bookmark" {
		// set provisioning
		applicationBoilerplate.Provisioning = applications.Provisioning{
			Policies: applications.ProvisioningPolicies{
				GracePeriod:  1,
				ProvPolicy:   "disabled",
				DeProvPolicy: "disabled",
				DeProvAction: "delete",
				AdoptionPolicy: applications.AdoptionPolicy{
					MatchingAttributes: []*applications.AttributeMapping{},
					RemediationPolicy: map[string]string{
						"policy": "NONE",
					},
				},
			},
		}
		// set providers
		applicationBoilerplate.Providers = applications.Providers{
			SAML: applications.SAML{
				Properties: applications.SAMLProperties{
					CompanyName:              " ",
					GenerateUniqueID:         "false",
					ValidateAuthnRequest:     "false",
					EncryptAssertion:         "false",
					ICIReservedSubjectNameID: " ",
					IncludeAllAttributes:     "false",
					UniqueID:                 " ",
					SignAuthnResponse:        "true",
					SignatureAlgorithm:       "RSA-SHA256",
					DefaultNameIdFormat:      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
					SessionNotOnOrAfter:      " ",
					ValidateLogoutRequest:    "ture",
					ValidateLogoutResponse:   "ture",
					UseMetaData:              "ture",
				},
			},
			SSO: applications.SSO{
				UserOptions:            " ",
				IDPInitiatedSSOSupport: "false",
			},
			Bookmark: applications.Bookmark{
				BookmarkURL: " ",
			},
		}
	}
}

func CreatePasswordPolicyBoilerplate(passwordPolicyBoilerplate *security.PasswordPolicy) {
	passwordPolicyBoilerplate.PolicyDescription = " "
	passwordPolicyBoilerplate.Schemas = []string{"urn:ietf:params:scim:schemas:ibm:core:3.0:policy:Password"}
	passwordPolicyBoilerplate.PasswordSecurity = security.PasswordSecurity{
		PwdInHistory:       1,
		PwdLockout:         true,
		PwdLockoutDuration: 1,
		PwdMaxAge:          1,
		PwdMaxFailure:      1,
		PwdMinAge:          1,
	}
	passwordPolicyBoilerplate.PasswordStrength = security.PasswordStrength{
		PasswordMaxConsecutiveRepeatedChars: 1,
		PasswordMaxRepeatedChars:            1,
		PasswordMinAlphaChars:               1,
		PasswordMinDiffChars:                1,
		PasswordMinLowerCaseChars:           1,
		PasswordMinNumberChars:              1,
		PasswordMinOtherChars:               1,
		PasswordMinSpecialChars:             1,
		PasswordMinUpperCaseChars:           1,
		PwdMinLength:                        1,
	}
}

func CreateIdentitySourceBoilerplate(identitySourceBoilerplate *authentication.IdentitySource) {
	identitySourceBoilerplate.Properties = append(identitySourceBoilerplate.Properties, authentication.IdentitySourceInstancesPropertiesData{Key: "", Value: "", Sensitive: false})
}

// This function helps in boilerplate generation to update Sign in options
func GetSignInOptionsBoilerplate() *SignInOptions {
	var signInOptions = &SignInOptions{
		InstanceName: "",
		Properties: []map[string]interface{}{
			{
				"key":       "show_admin_user",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_admin_user_qr",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_admin_user_fido",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_end_user",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_end_user_qr",
				"value":     "false",
				"sensitive": false,
			},
			{
				"key":       "show_end_user_fido",
				"value":     "false",
				"sensitive": false,
			},
		},
	}
	return signInOptions
}
