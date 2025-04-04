package module

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibm-security-verify/verifyctl/pkg/module/openapi"
	xhttp "github.com/ibm-security-verify/verifyctl/pkg/util/http"
)

type VerifyError struct {
	MessageID          string `json:"messageId" yaml:"messageId"`
	MessageDescription string `json:"messageDescription" yaml:"messageDescription"`
}

func HandleCommonErrors(ctx context.Context, response *xhttp.Response, defaultError string) error {
	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("Login again.")
	}

	if response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("You are not allowed to make this request. Check the client or application entitlements.")
	}

	if response.StatusCode == http.StatusBadRequest {
		var errorMessage VerifyError
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

// when any API can generete multiple response structure for same response code
// we use this custom parse method to parse the response
func CustomParse(rsp *http.Response, rspErr error) (*openapi.GetAllAttributesObject, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &openapi.GetAllAttributesObject{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}
