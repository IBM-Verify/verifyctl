package http

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

var (
	defaultClient *http.Client = &http.Client{
		Transport:     http.DefaultTransport,
		Timeout:       30 * time.Minute,
		CheckRedirect: noRedirects,
	}
)

type defaultClientx struct {
	client *http.Client
}

func NewDefaultClient() Clientx {
	return &defaultClientx{
		client: defaultClient,
	}
}

// Get makes a HTTP GET call and returns the response
func (c *defaultClientx) Get(ctx context.Context, url *url.URL, headers http.Header) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

// Post makes a HTTP POST call and returns the response
func (c *defaultClientx) Post(ctx context.Context, url *url.URL, headers http.Header, body []byte) (*Response, error) {
	bodyReader := bytes.NewReader([]byte(body))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

// PostMultipart makes a HTTP POST call with content-type set to multipart/form-data and returns the response
func (c *defaultClientx) PostMultipart(ctx context.Context, url *url.URL, headers http.Header, files map[string][]byte, fields map[string]string) (*Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	defer writer.Close()

	for fileName, data := range files {
		part, err := writer.CreateFormFile(fileName, fileName)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(part, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
	}

	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), body)
	if err != nil {
		return nil, err
	}

	request.Header.Add("content-type", "multipart/form-data")
	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

// Put makes a HTTP PUT call and returns the response
func (c *defaultClientx) Put(ctx context.Context, url *url.URL, headers http.Header, body []byte) (*Response, error) {
	bodyReader := bytes.NewReader([]byte(body))
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

// PutMultipart makes a HTTP PUT call with content-type set to multipart/form-data and returns the response
func (c *defaultClientx) PutMultipart(ctx context.Context, url *url.URL, headers http.Header, files map[string][]byte, fields map[string]string) (*Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	defer writer.Close()

	for fileName, data := range files {
		part, err := writer.CreateFormFile(fileName, fileName)
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(part, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
	}

	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return nil, err
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url.String(), body)
	if err != nil {
		return nil, err
	}

	request.Header.Add("content-type", "multipart/form-data")
	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

// Patch makes a HTTP PATCH call and returns the response
func (c *defaultClientx) Patch(ctx context.Context, url *url.URL, headers http.Header, body []byte) (*Response, error) {
	bodyReader := bytes.NewReader([]byte(body))
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, url.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

// Delete makes a HTTP DELETE call and returns the response
func (c *defaultClientx) Delete(ctx context.Context, url *url.URL, headers http.Header) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, url.String(), nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		request.Header.Add(k, v[0])
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	respObj := &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
	}

	if response.Body != nil {
		resBody, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, errorsx.G11NError("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

func noRedirects(req *http.Request, via []*http.Request) error {
	return errorsx.G11NError("redirects not allowed")
}
