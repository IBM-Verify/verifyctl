// Package core contains common helpers and types
package http

import (
	"context"
	"net/http"
	"net/url"
)

// Clientx performs the common HTTP operations that would be typically performed by
// an HTTP client.
type Clientx interface {
	// Get makes a HTTP GET call and returns the response
	Get(ctx context.Context, url *url.URL, headers http.Header) (*Response, error)

	// Post makes a HTTP POST call and returns the response
	Post(ctx context.Context, url *url.URL, headers http.Header, body []byte) (*Response, error)

	// Put makes a HTTP PUT call and returns the response
	Put(ctx context.Context, url *url.URL, headers http.Header, body []byte) (*Response, error)

	// Patch makes a HTTP PATCH call and returns the response
	Patch(ctx context.Context, url *url.URL, headers http.Header, body []byte) (*Response, error)

	// Delete makes a HTTP DELETE call and returns the response
	Delete(ctx context.Context, url *url.URL, headers http.Header) (*Response, error)
}

// Response includes the StatusCode, Body and Headers of a request.
type Response struct {
	// StatusCode is the HTTP status code.
	// For example, http.StatusOK.
	StatusCode int
	// Body returns the raw body as bytes.
	Body []byte
	// Headers returns the HTTP response headers.
	Headers http.Header
}
