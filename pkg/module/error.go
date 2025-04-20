package module

import (
	"context"
	"encoding/json"
	"net/http"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	xhttp "github.com/ibm-verify/verifyctl/pkg/util/http"
)

func HandleCommonErrorsX(ctx context.Context, response *xhttp.Response, defaultError string) error {
	if response.StatusCode == http.StatusUnauthorized {
		return errorsx.G11NError("Login again.")
	}

	if response.StatusCode == http.StatusForbidden {
		return errorsx.G11NError("You are not allowed to make this request. Check the client or application entitlements.")
	}

	if response.StatusCode == http.StatusBadRequest {
		var errorMessage errorsx.VerifyError
		if err := json.Unmarshal(response.Body, &errorMessage); err != nil {
			return errorsx.G11NError("bad request: %s", defaultError)
		}
		// If the expected fields are not populated, return the raw response body.
		if errorMessage.MessageID == "" && errorMessage.MessageDescription == "" {
			return errorsx.G11NError("bad request: %s", string(response.Body))
		}
		return errorsx.G11NError("%s %s", errorMessage.MessageID, errorMessage.MessageDescription)
	}

	if response.StatusCode == http.StatusNotFound {
		return errorsx.G11NError("Resource not found")
	}

	return nil
}
