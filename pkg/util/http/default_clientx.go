package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
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
			return nil, fmt.Errorf("unable to extract the body")
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
			return nil, fmt.Errorf("unable to extract the body")
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
			return nil, fmt.Errorf("unable to extract the body")
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
			return nil, fmt.Errorf("unable to extract the body")
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
			return nil, fmt.Errorf("unable to extract the body")
		}

		respObj.Body = resBody
	}

	return respObj, nil
}

func noRedirects(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("redirects not allowed")
}
