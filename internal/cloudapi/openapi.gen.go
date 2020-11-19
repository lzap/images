// Package cloudapi provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package cloudapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/go-chi/chi"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// AWSUploadRequestOptions defines model for AWSUploadRequestOptions.
type AWSUploadRequestOptions struct {
	Ec2    AWSUploadRequestOptionsEc2 `json:"ec2"`
	Region string                     `json:"region"`
	S3     AWSUploadRequestOptionsS3  `json:"s3"`
}

// AWSUploadRequestOptionsEc2 defines model for AWSUploadRequestOptionsEc2.
type AWSUploadRequestOptionsEc2 struct {
	AccessKeyId       string    `json:"access_key_id"`
	SecretAccessKey   string    `json:"secret_access_key"`
	ShareWithAccounts *[]string `json:"share_with_accounts,omitempty"`
	SnapshotName      *string   `json:"snapshot_name,omitempty"`
}

// AWSUploadRequestOptionsS3 defines model for AWSUploadRequestOptionsS3.
type AWSUploadRequestOptionsS3 struct {
	AccessKeyId     string `json:"access_key_id"`
	Bucket          string `json:"bucket"`
	SecretAccessKey string `json:"secret_access_key"`
}

// AWSUploadStatus defines model for AWSUploadStatus.
type AWSUploadStatus struct {
	AmiId *string `json:"ami_id,omitempty"`
}

// ComposeRequest defines model for ComposeRequest.
type ComposeRequest struct {
	Customizations *Customizations `json:"customizations,omitempty"`
	Distribution   string          `json:"distribution"`
	ImageRequests  []ImageRequest  `json:"image_requests"`
}

// ComposeResult defines model for ComposeResult.
type ComposeResult struct {
	Id string `json:"id"`
}

// ComposeStatus defines model for ComposeStatus.
type ComposeStatus struct {
	ImageStatuses *[]ImageStatus `json:"image_statuses,omitempty"`
	Status        string         `json:"status"`
}

// Customizations defines model for Customizations.
type Customizations struct {
	Subscription *Subscription `json:"subscription,omitempty"`
}

// ImageRequest defines model for ImageRequest.
type ImageRequest struct {
	Architecture   string          `json:"architecture"`
	ImageType      string          `json:"image_type"`
	Repositories   []Repository    `json:"repositories"`
	UploadRequests []UploadRequest `json:"upload_requests"`
}

// ImageStatus defines model for ImageStatus.
type ImageStatus struct {
	Status         string          `json:"status"`
	UploadStatuses *[]UploadStatus `json:"upload_statuses,omitempty"`
}

// Repository defines model for Repository.
type Repository struct {
	Baseurl    *string `json:"baseurl,omitempty"`
	Metalink   *string `json:"metalink,omitempty"`
	Mirrorlist *string `json:"mirrorlist,omitempty"`
	Rhsm       bool    `json:"rhsm"`
}

// Subscription defines model for Subscription.
type Subscription struct {
	ActivationKey string `json:"activation-key"`
	BaseUrl       string `json:"base-url"`
	Insights      bool   `json:"insights"`
	Organization  int    `json:"organization"`
	ServerUrl     string `json:"server-url"`
}

// UploadRequest defines model for UploadRequest.
type UploadRequest struct {
	Options interface{} `json:"options"`
	Type    string      `json:"type"`
}

// UploadStatus defines model for UploadStatus.
type UploadStatus interface{}

// ComposeJSONBody defines parameters for Compose.
type ComposeJSONBody ComposeRequest

// ComposeRequestBody defines body for Compose for application/json ContentType.
type ComposeJSONRequestBody ComposeJSONBody

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A callback for modifying requests which are generated before sending over
	// the network.
	RequestEditor RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = http.DefaultClient
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditor = fn
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// Compose request  with any body
	ComposeWithBody(ctx context.Context, contentType string, body io.Reader) (*http.Response, error)

	Compose(ctx context.Context, body ComposeJSONRequestBody) (*http.Response, error)

	// ComposeStatus request
	ComposeStatus(ctx context.Context, id string) (*http.Response, error)
}

func (c *Client) ComposeWithBody(ctx context.Context, contentType string, body io.Reader) (*http.Response, error) {
	req, err := NewComposeRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

func (c *Client) Compose(ctx context.Context, body ComposeJSONRequestBody) (*http.Response, error) {
	req, err := NewComposeRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

func (c *Client) ComposeStatus(ctx context.Context, id string) (*http.Response, error) {
	req, err := NewComposeStatusRequest(c.Server, id)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

// NewComposeRequest calls the generic Compose builder with application/json body
func NewComposeRequest(server string, body ComposeJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewComposeRequestWithBody(server, "application/json", bodyReader)
}

// NewComposeRequestWithBody generates requests for Compose with any type of body
func NewComposeRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/compose")
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryUrl.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// NewComposeStatusRequest generates requests for ComposeStatus
func NewComposeStatusRequest(server string, id string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParam("simple", false, "id", id)
	if err != nil {
		return nil, err
	}

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/compose/%s", pathParam0)
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// Compose request  with any body
	ComposeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader) (*ComposeResponse, error)

	ComposeWithResponse(ctx context.Context, body ComposeJSONRequestBody) (*ComposeResponse, error)

	// ComposeStatus request
	ComposeStatusWithResponse(ctx context.Context, id string) (*ComposeStatusResponse, error)
}

type ComposeResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON201      *ComposeResult
}

// Status returns HTTPResponse.Status
func (r ComposeResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ComposeResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ComposeStatusResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *ComposeStatus
}

// Status returns HTTPResponse.Status
func (r ComposeStatusResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ComposeStatusResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// ComposeWithBodyWithResponse request with arbitrary body returning *ComposeResponse
func (c *ClientWithResponses) ComposeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader) (*ComposeResponse, error) {
	rsp, err := c.ComposeWithBody(ctx, contentType, body)
	if err != nil {
		return nil, err
	}
	return ParseComposeResponse(rsp)
}

func (c *ClientWithResponses) ComposeWithResponse(ctx context.Context, body ComposeJSONRequestBody) (*ComposeResponse, error) {
	rsp, err := c.Compose(ctx, body)
	if err != nil {
		return nil, err
	}
	return ParseComposeResponse(rsp)
}

// ComposeStatusWithResponse request returning *ComposeStatusResponse
func (c *ClientWithResponses) ComposeStatusWithResponse(ctx context.Context, id string) (*ComposeStatusResponse, error) {
	rsp, err := c.ComposeStatus(ctx, id)
	if err != nil {
		return nil, err
	}
	return ParseComposeStatusResponse(rsp)
}

// ParseComposeResponse parses an HTTP response from a ComposeWithResponse call
func ParseComposeResponse(rsp *http.Response) (*ComposeResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &ComposeResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 201:
		var dest ComposeResult
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON201 = &dest

	}

	return response, nil
}

// ParseComposeStatusResponse parses an HTTP response from a ComposeStatusWithResponse call
func ParseComposeStatusResponse(rsp *http.Response) (*ComposeStatusResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &ComposeStatusResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest ComposeStatus
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create compose
	// (POST /compose)
	Compose(w http.ResponseWriter, r *http.Request)
	// The status of a compose
	// (GET /compose/{id})
	ComposeStatus(w http.ResponseWriter, r *http.Request, id string)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// Compose operation middleware
func (siw *ServerInterfaceWrapper) Compose(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	siw.Handler.Compose(w, r.WithContext(ctx))
}

// ComposeStatus operation middleware
func (siw *ServerInterfaceWrapper) ComposeStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameter("simple", false, "id", chi.URLParam(r, "id"), &id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid format for parameter id: %s", err), http.StatusBadRequest)
		return
	}

	siw.Handler.ComposeStatus(w, r.WithContext(ctx), id)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerFromMux(si, chi.NewRouter())
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	r.Group(func(r chi.Router) {
		r.Post("/compose", wrapper.Compose)
	})
	r.Group(func(r chi.Router) {
		r.Get("/compose/{id}", wrapper.ComposeStatus)
	})

	return r
}
