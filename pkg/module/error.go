package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	xhttp "github.com/ibm-verify/verifyctl/pkg/util/http"
)

type SimpleError struct {
	Message string
}

func (e *SimpleError) Error() string {
	return e.Message
}

func MakeSimpleError(message string) error {
	return &SimpleError{
		Message: message,
	}
}

func HandleCommonErrorsX(ctx context.Context, response *xhttp.Response, defaultError string) error {
	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("Login again.")
	}

	if response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("You are not allowed to make this request. Check the client or application entitlements.")
	}

	if response.StatusCode == http.StatusBadRequest {
		var errorMessage errorsx.VerifyError
		if err := json.Unmarshal(response.Body, &errorMessage); err != nil {
			return fmt.Errorf("bad request: %s", defaultError)
		}
		// If the expected fields are not populated, return the raw response body.
		if errorMessage.MessageID == "" && errorMessage.MessageDescription == "" {
			return fmt.Errorf("bad request: %s", string(response.Body))
		}
		return fmt.Errorf("%s %s", errorMessage.MessageID, errorMessage.MessageDescription)
	}

	if response.StatusCode == http.StatusNotFound {
		return fmt.Errorf("Resource not found")
	}

	return nil
}
