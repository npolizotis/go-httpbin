package httpbin

import (
	"net/http"
	"net/url"
	"time"

	"github.com/julienschmidt/httprouter"
)

// Default configuration values
const (
	DefaultMaxBodySize int64 = 1024 * 1024
	DefaultMaxDuration       = 10 * time.Second
)

const jsonContentType = "application/json; encoding=utf-8"
const htmlContentType = "text/html; charset=utf-8"

type headersResponse struct {
	Headers http.Header `json:"headers"`
}

type ipResponse struct {
	Origin string `json:"origin"`
}

type userAgentResponse struct {
	UserAgent string `json:"user-agent"`
}

type getResponse struct {
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	URL     string      `json:"url"`
}

// A generic response for any incoming request that might contain a body
type bodyResponse struct {
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	URL     string      `json:"url"`

	Data  string              `json:"data"`
	Files map[string][]string `json:"files"`
	Form  map[string][]string `json:"form"`
	JSON  interface{}         `json:"json"`
}

type cookiesResponse map[string]string

type authResponse struct {
	Authorized bool   `json:"authorized"`
	User       string `json:"user"`
}

type gzipResponse struct {
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	Gzipped bool        `json:"gzipped"`
}

type deflateResponse struct {
	Headers  http.Header `json:"headers"`
	Origin   string      `json:"origin"`
	Deflated bool        `json:"deflated"`
}

// An actual stream response body will be made up of one or more of these
// structs, encoded as JSON and separated by newlines
type streamResponse struct {
	ID      int         `json:"id"`
	Args    url.Values  `json:"args"`
	Headers http.Header `json:"headers"`
	Origin  string      `json:"origin"`
	URL     string      `json:"url"`
}

type uuidResponse struct {
	UUID string `json:"uuid"`
}

type bearerResponse struct {
	Authenticated bool   `json:"authenticated"`
	Token         string `json:"token"`
}

// HTTPBin contains the business logic
type HTTPBin struct {
	// Max size of an incoming request generated response body, in bytes
	MaxBodySize int64

	// Max duration of a request, for those requests that allow user control
	// over timing (e.g. /delay)
	MaxDuration time.Duration

	// Observer called with the result of each handled request
	Observer Observer

	// Default parameter values
	DefaultParams DefaultParams
}

// DefaultParams defines default parameter values
type DefaultParams struct {
	DripDuration time.Duration
	DripDelay    time.Duration
	DripNumBytes int64
}

// DefaultDefaultParams defines the DefaultParams that are used by default. In
// general, these should match the original httpbin.org's defaults.
var DefaultDefaultParams = DefaultParams{
	DripDuration: 2 * time.Second,
	DripDelay:    2 * time.Second,
	DripNumBytes: 10,
}

type myRouter struct {
	httprouter.Router
}

func (r *myRouter) HandlerFunc(method, path string, hf http.HandlerFunc) {
	r.Router.HandlerFunc(method, path, hf)
	if method == http.MethodGet {
		r.Router.HandlerFunc(http.MethodHead, path, hf)
	}
}

func newRouter() *myRouter {
	r := &myRouter{
		Router: *httprouter.New(),
	}
	r.RedirectTrailingSlash = false
	return r
}

// Handler returns an http.Handler that exposes all HTTPBin endpoints
func (h *HTTPBin) Handler() http.Handler {
	mux := newRouter()

	mux.HandlerFunc(http.MethodGet, "/", h.Index)
	mux.HandlerFunc(http.MethodGet, "/forms/post", h.FormsPost)
	mux.HandlerFunc(http.MethodGet, "/encoding/utf8", h.UTF8)

	mux.HandlerFunc(http.MethodGet, "/get", h.Get)
	mux.HandlerFunc(http.MethodPost, "/post", h.RequestWithBody)
	mux.HandlerFunc(http.MethodPut, "/put", h.RequestWithBody)
	mux.HandlerFunc(http.MethodPatch, "/patch", h.RequestWithBody)
	mux.HandlerFunc(http.MethodDelete, "/delete", h.RequestWithBody)

	mux.HandlerFunc(http.MethodGet, "/ip", h.IP)
	mux.HandlerFunc(http.MethodGet, "/user-agent", h.UserAgent)
	mux.HandlerFunc(http.MethodGet, "/headers", h.Headers)
	mux.HandlerFunc(http.MethodGet, "/response-headers", h.ResponseHeaders)

	mux.GET("/status/", h.Status)
	mux.GET("/status/:code", h.Status)

	mux.HandlerFunc(http.MethodGet, "/redirect/*path", h.Redirect)
	mux.HandlerFunc(http.MethodGet, "/relative-redirect/*path", h.RelativeRedirect)
	mux.HandlerFunc(http.MethodGet, "/absolute-redirect/*path", h.AbsoluteRedirect)
	mux.HandlerFunc(http.MethodGet, "/redirect-to", h.RedirectTo)

	mux.HandlerFunc(http.MethodGet, "/cookies", h.Cookies)
	mux.HandlerFunc(http.MethodGet, "/cookies/set", h.SetCookies)
	mux.HandlerFunc(http.MethodGet, "/cookies/delete", h.DeleteCookies)

	mux.GET("/basic-auth/", h.BasicAuth)
	mux.GET("/basic-auth/:user/:password", h.BasicAuth)

	mux.GET("/hidden-basic-auth/", h.HiddenBasicAuth)
	mux.GET("/hidden-basic-auth/:user/:password", h.HiddenBasicAuth)

	mux.GET("/digest-auth/:qop/:user/:passwd", h.DigestAuth)
	mux.GET("/digest-auth/:qop/:user/:passwd/:algorithm", h.DigestAuth)
	mux.HandlerFunc(http.MethodGet, "/bearer", h.Bearer)

	mux.HandlerFunc(http.MethodGet, "/deflate", h.Deflate)
	mux.HandlerFunc(http.MethodGet, "/gzip", h.Gzip)

	mux.GET("/stream/:n", h.Stream)
	mux.GET("/delay/:delay", h.Delay)
	mux.HandlerFunc(http.MethodGet, "/drip", h.Drip)

	mux.GET("/range/", h.Range)
	mux.GET("/range/:range", h.Range)
	mux.GET("/bytes/:numBytes", h.Bytes)
	mux.GET("/stream-bytes/:numBytes", h.StreamBytes)

	mux.HandlerFunc(http.MethodGet, "/html", h.HTML)
	mux.HandlerFunc(http.MethodGet, "/robots.txt", h.Robots)
	mux.HandlerFunc(http.MethodGet, "/deny", h.Deny)

	mux.HandlerFunc(http.MethodGet, "/cache", h.Cache)
	mux.GET("/cache/:seconds", h.CacheControl)
	mux.GET("/etag/:etag", h.ETag)

	mux.GET("/links/:n", h.Links)
	mux.GET("/links/:n/:offset", h.Links)

	mux.HandlerFunc(http.MethodGet, "/image", h.ImageAccept)
	mux.GET("/image/:kind", h.Image)
	mux.HandlerFunc(http.MethodGet, "/xml", h.XML)
	mux.HandlerFunc(http.MethodGet, "/json", h.JSON)

	mux.HandlerFunc(http.MethodGet, "/uuid", h.UUID)
	
	mux.GET("/base64/",h.Base64)
	mux.GET("/base64/:arg1", h.Base64)
	mux.GET("/base64/:arg1/",h.Base64)
	mux.GET("/base64/:arg1/:arg2", h.Base64)
	mux.GET("/base64/:arg1/:arg2/*path", h.Base64)

	// existing httpbin endpoints that we do not support
	mux.HandlerFunc(http.MethodGet, "/brotli", notImplementedHandler)

	// Apply global middleware
	var handler http.Handler
	handler = mux
	handler = limitRequestSize(h.MaxBodySize, handler)
	handler = preflight(handler)
	handler = autohead(handler)
	if h.Observer != nil {
		handler = observe(h.Observer, handler)
	}

	return handler
}

// New creates a new HTTPBin instance
func New(opts ...OptionFunc) *HTTPBin {
	h := &HTTPBin{
		MaxBodySize:   DefaultMaxBodySize,
		MaxDuration:   DefaultMaxDuration,
		DefaultParams: DefaultDefaultParams,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// OptionFunc uses the "functional options" pattern to customize an HTTPBin
// instance
type OptionFunc func(*HTTPBin)

// WithDefaultParams sets the default params handlers will use
func WithDefaultParams(defaultParams DefaultParams) OptionFunc {
	return func(h *HTTPBin) {
		h.DefaultParams = defaultParams
	}
}

// WithMaxBodySize sets the maximum amount of memory
func WithMaxBodySize(m int64) OptionFunc {
	return func(h *HTTPBin) {
		h.MaxBodySize = m
	}
}

// WithMaxDuration sets the maximum amount of time httpbin may take to respond
func WithMaxDuration(d time.Duration) OptionFunc {
	return func(h *HTTPBin) {
		h.MaxDuration = d
	}
}

// WithObserver sets the request observer callback
func WithObserver(o Observer) OptionFunc {
	return func(h *HTTPBin) {
		h.Observer = o
	}
}
