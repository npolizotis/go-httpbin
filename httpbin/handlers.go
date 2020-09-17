package httpbin

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/npolizotis/go-httpbin/httpbin/assets"
	"github.com/npolizotis/go-httpbin/httpbin/digest"
)

var acceptedMediaTypes = []string{
	"image/webp",
	"image/svg+xml",
	"image/jpeg",
	"image/png",
	"image/",
}

func notImplementedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// Index renders an HTML index page
func (h *HTTPBin) Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' camo.githubusercontent.com")
	writeHTML(w, assets.MustLoad("index.html"), http.StatusOK)
}

// FormsPost renders an HTML form that submits a request to the /post endpoint
func (h *HTTPBin) FormsPost(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, assets.MustLoad("forms-post.html"), http.StatusOK)
}

// UTF8 renders an HTML encoding stress test
func (h *HTTPBin) UTF8(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, assets.MustLoad("utf8.html"), http.StatusOK)
}

// Get handles HTTP GET requests
func (h *HTTPBin) Get(w http.ResponseWriter, r *http.Request) {
	resp := &getResponse{
		Args:    r.URL.Query(),
		Headers: getRequestHeaders(r),
		Origin:  getOrigin(r),
		URL:     getURL(r).String(),
	}
	body, _ := json.Marshal(resp)
	writeJSON(w, body, http.StatusOK)
}

// RequestWithBody handles POST, PUT, and PATCH requests
func (h *HTTPBin) RequestWithBody(w http.ResponseWriter, r *http.Request) {
	resp := &bodyResponse{
		Args:    r.URL.Query(),
		Headers: getRequestHeaders(r),
		Origin:  getOrigin(r),
		URL:     getURL(r).String(),
	}

	err := parseBody(w, r, resp)
	if err != nil {
		http.Error(w, fmt.Sprintf("error parsing request body: %s", err), http.StatusBadRequest)
		return
	}

	body, _ := json.Marshal(resp)
	writeJSON(w, body, http.StatusOK)
}

// Gzip returns a gzipped response
func (h *HTTPBin) Gzip(w http.ResponseWriter, r *http.Request) {
	resp := &gzipResponse{
		Headers: getRequestHeaders(r),
		Origin:  getOrigin(r),
		Gzipped: true,
	}
	body, _ := json.Marshal(resp)

	buf := &bytes.Buffer{}
	gzw := gzip.NewWriter(buf)
	gzw.Write(body)
	gzw.Close()

	gzBody := buf.Bytes()

	w.Header().Set("Content-Encoding", "gzip")
	writeJSON(w, gzBody, http.StatusOK)
}

// Deflate returns a gzipped response
func (h *HTTPBin) Deflate(w http.ResponseWriter, r *http.Request) {
	resp := &deflateResponse{
		Headers:  getRequestHeaders(r),
		Origin:   getOrigin(r),
		Deflated: true,
	}
	body, _ := json.Marshal(resp)

	buf := &bytes.Buffer{}
	w2 := zlib.NewWriter(buf)
	w2.Write(body)
	w2.Close()

	compressedBody := buf.Bytes()

	w.Header().Set("Content-Encoding", "deflate")
	writeJSON(w, compressedBody, http.StatusOK)
}

// IP echoes the IP address of the incoming request
func (h *HTTPBin) IP(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(&ipResponse{
		Origin: getOrigin(r),
	})
	writeJSON(w, body, http.StatusOK)
}

// UserAgent echoes the incoming User-Agent header
func (h *HTTPBin) UserAgent(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(&userAgentResponse{
		UserAgent: r.Header.Get("User-Agent"),
	})
	writeJSON(w, body, http.StatusOK)
}

// Headers echoes the incoming request headers
func (h *HTTPBin) Headers(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(&headersResponse{
		Headers: getRequestHeaders(r),
	})
	writeJSON(w, body, http.StatusOK)
}

// Status responds with the specified status code. TODO: support random choice
// from multiple, optionally weighted status codes.
func (h *HTTPBin) Status(w http.ResponseWriter, r *http.Request, param httprouter.Params) {
	codeStr := param.ByName("code")
	if codeStr == "" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	type statusCase struct {
		headers map[string]string
		body    []byte
	}

	redirectHeaders := &statusCase{
		headers: map[string]string{
			"Location": "/redirect/1",
		},
	}
	notAcceptableBody, _ := json.Marshal(map[string]interface{}{
		"message": "Client did not request a supported media type",
		"accept":  acceptedMediaTypes,
	})

	specialCases := map[int]*statusCase{
		301: redirectHeaders,
		302: redirectHeaders,
		303: redirectHeaders,
		305: redirectHeaders,
		307: redirectHeaders,
		401: {
			headers: map[string]string{
				"WWW-Authenticate": `Basic realm="Fake Realm"`,
			},
		},
		402: {
			body: []byte("Fuck you, pay me!"),
			headers: map[string]string{
				"X-More-Info": "http://vimeo.com/22053820",
			},
		},
		406: {
			body: notAcceptableBody,
			headers: map[string]string{
				"Content-Type": jsonContentType,
			},
		},
		407: {
			headers: map[string]string{
				"Proxy-Authenticate": `Basic realm="Fake Realm"`,
			},
		},
		418: {
			body: []byte("I'm a teapot!"),
			headers: map[string]string{
				"X-More-Info": "http://tools.ietf.org/html/rfc2324",
			},
		},
	}

	if specialCase, ok := specialCases[code]; ok {
		if specialCase.headers != nil {
			for key, val := range specialCase.headers {
				w.Header().Set(key, val)
			}
		}
		w.WriteHeader(code)
		if specialCase.body != nil {
			w.Write(specialCase.body)
		}
	} else {
		w.WriteHeader(code)
	}
}

// ResponseHeaders responds with a map of header values
func (h *HTTPBin) ResponseHeaders(w http.ResponseWriter, r *http.Request) {
	args := r.URL.Query()
	for k, vs := range args {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	body, _ := json.Marshal(args)
	if contentType := w.Header().Get("Content-Type"); contentType == "" {
		w.Header().Set("Content-Type", jsonContentType)
	}
	w.Write(body)
}

func redirectLocation(r *http.Request, relative bool, n int) string {
	var location string
	var path string

	if n < 1 {
		path = "/get"
	} else if relative {
		path = fmt.Sprintf("/relative-redirect/%d", n)
	} else {
		path = fmt.Sprintf("/absolute-redirect/%d", n)
	}

	if relative {
		location = path
	} else {
		u := getURL(r)
		u.Path = path
		u.RawQuery = ""
		location = u.String()
	}

	return location
}

func doRedirect(w http.ResponseWriter, r *http.Request, relative bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil || n < 1 {
		http.Error(w, "Invalid redirect", http.StatusBadRequest)
		return
	}

	w.Header().Set("Location", redirectLocation(r, relative, n-1))
	w.WriteHeader(http.StatusFound)
}

// Redirect responds with 302 redirect a given number of times. Defaults to a
// relative redirect, but an ?absolute=true query param will trigger an
// absolute redirect.
func (h *HTTPBin) Redirect(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	relative := strings.ToLower(params.Get("absolute")) != "true"
	doRedirect(w, r, relative)
}

// RelativeRedirect responds with an HTTP 302 redirect a given number of times
func (h *HTTPBin) RelativeRedirect(w http.ResponseWriter, r *http.Request) {
	doRedirect(w, r, true)
}

// AbsoluteRedirect responds with an HTTP 302 redirect a given number of times
func (h *HTTPBin) AbsoluteRedirect(w http.ResponseWriter, r *http.Request) {
	doRedirect(w, r, false)
}

// RedirectTo responds with a redirect to a specific URL with an optional
// status code, which defaults to 302
func (h *HTTPBin) RedirectTo(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	url := q.Get("url")
	if url == "" {
		http.Error(w, "Missing URL", http.StatusBadRequest)
		return
	}

	var err error
	statusCode := http.StatusFound
	rawStatusCode := q.Get("status_code")
	if rawStatusCode != "" {
		statusCode, err = strconv.Atoi(q.Get("status_code"))
		if err != nil || statusCode < 300 || statusCode > 399 {
			http.Error(w, "Invalid status code", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Location", url)
	w.WriteHeader(statusCode)
}

// Cookies responds with the cookies in the incoming request
func (h *HTTPBin) Cookies(w http.ResponseWriter, r *http.Request) {
	resp := cookiesResponse{}
	for _, c := range r.Cookies() {
		resp[c.Name] = c.Value
	}
	body, _ := json.Marshal(resp)
	writeJSON(w, body, http.StatusOK)
}

// SetCookies sets cookies as specified in query params and redirects to
// Cookies endpoint
func (h *HTTPBin) SetCookies(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	for k := range params {
		http.SetCookie(w, &http.Cookie{
			Name:     k,
			Value:    params.Get(k),
			HttpOnly: true,
		})
	}
	w.Header().Set("Location", "/cookies")
	w.WriteHeader(http.StatusFound)
}

// DeleteCookies deletes cookies specified in query params and redirects to
// Cookies endpoint
func (h *HTTPBin) DeleteCookies(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	for k := range params {
		http.SetCookie(w, &http.Cookie{
			Name:     k,
			Value:    params.Get(k),
			HttpOnly: true,
			MaxAge:   -1,
			Expires:  time.Now().Add(-1 * 24 * 365 * time.Hour),
		})
	}
	w.Header().Set("Location", "/cookies")
	w.WriteHeader(http.StatusFound)
}

// BasicAuth requires basic authentication
func (h *HTTPBin) BasicAuth(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	expectedUser := params.ByName("user")
	expectedPass := params.ByName("password")

	if expectedUser == "" || expectedPass == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	givenUser, givenPass, _ := r.BasicAuth()

	status := http.StatusOK
	authorized := givenUser == expectedUser && givenPass == expectedPass
	if !authorized {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="Fake Realm"`)
	}

	body, _ := json.Marshal(&authResponse{
		Authorized: authorized,
		User:       givenUser,
	})
	writeJSON(w, body, status)
}

// HiddenBasicAuth requires HTTP Basic authentication but returns a status of
// 404 if the request is unauthorized
func (h *HTTPBin) HiddenBasicAuth(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	expectedUser := params.ByName("user")
	expectedPass := params.ByName("password")

	if expectedUser == "" || expectedPass == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	givenUser, givenPass, _ := r.BasicAuth()

	authorized := givenUser == expectedUser && givenPass == expectedPass
	if !authorized {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	body, _ := json.Marshal(&authResponse{
		Authorized: authorized,
		User:       givenUser,
	})
	writeJSON(w, body, http.StatusOK)
}

// Stream responds with max(n, 100) lines of JSON-encoded request data.
func (h *HTTPBin) Stream(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	n, err := strconv.Atoi(params.ByName("n"))
	if err != nil {
		http.Error(w, "Invalid integer", http.StatusBadRequest)
		return
	}

	if n > 100 {
		n = 100
	} else if n < 1 {
		n = 1
	}

	resp := &streamResponse{
		Args:    r.URL.Query(),
		Headers: getRequestHeaders(r),
		Origin:  getOrigin(r),
		URL:     getURL(r).String(),
	}

	f := w.(http.Flusher)
	for i := 0; i < n; i++ {
		resp.ID = i
		line, _ := json.Marshal(resp)
		w.Write(line)
		w.Write([]byte("\n"))
		f.Flush()
	}
}

// Delay waits for a given amount of time before responding, where the time may
// be specified as a golang-style duration or seconds in floating point.
func (h *HTTPBin) Delay(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	delay, err := parseBoundedDuration(params.ByName("delay"), 0, h.MaxDuration)
	if err != nil {
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}

	select {
	case <-r.Context().Done():
		return
	case <-time.After(delay):
	}
	h.RequestWithBody(w, r)
}

// Drip returns data over a duration after an optional initial delay, then
// (optionally) returns with the given status code.
func (h *HTTPBin) Drip(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	duration := time.Duration(0)
	delay := time.Duration(0)
	numbytes := int64(10)
	code := http.StatusOK

	var err error

	userDuration := q.Get("duration")
	if userDuration != "" {
		duration, err = parseBoundedDuration(userDuration, 0, h.MaxDuration)
		if err != nil {
			http.Error(w, "Invalid duration", http.StatusBadRequest)
			return
		}
	}

	userDelay := q.Get("delay")
	if userDelay != "" {
		delay, err = parseBoundedDuration(userDelay, 0, h.MaxDuration)
		if err != nil {
			http.Error(w, "Invalid delay", http.StatusBadRequest)
			return
		}
	}

	userNumBytes := q.Get("numbytes")
	if userNumBytes != "" {
		numbytes, err = strconv.ParseInt(userNumBytes, 10, 64)
		if err != nil || numbytes <= 0 || numbytes > h.MaxBodySize {
			http.Error(w, "Invalid numbytes", http.StatusBadRequest)
			return
		}
	}

	userCode := q.Get("code")
	if userCode != "" {
		code, err = strconv.Atoi(userCode)
		if err != nil || code < 100 || code >= 600 {
			http.Error(w, "Invalid code", http.StatusBadRequest)
			return
		}
	}

	if duration+delay > h.MaxDuration {
		http.Error(w, "Too much time", http.StatusBadRequest)
		return
	}

	pause := duration / time.Duration(numbytes)

	select {
	case <-r.Context().Done():
		return
	case <-time.After(delay):
	}

	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/octet-stream")

	f := w.(http.Flusher)
	for i := int64(0); i < numbytes; i++ {
		w.Write([]byte("*"))
		f.Flush()

		select {
		case <-r.Context().Done():
			return
		case <-time.After(pause):
		}
	}
}

// Range returns up to N bytes, with support for HTTP Range requests.
//
// This departs from httpbin by not supporting the chunk_size or duration
// parameters.
func (h *HTTPBin) Range(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	numBytes, err := strconv.ParseInt(params.ByName("range"), 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Add("ETag", fmt.Sprintf("range%d", numBytes))
	w.Header().Add("Accept-Ranges", "bytes")

	if numBytes <= 0 || numBytes > h.MaxBodySize {
		http.Error(w, "Invalid number of bytes", http.StatusBadRequest)
		return
	}

	content := newSyntheticByteStream(numBytes, func(offset int64) byte {
		return byte(97 + (offset % 26))
	})
	var modtime time.Time
	http.ServeContent(w, r, "", modtime, content)
}

// HTML renders a basic HTML page
func (h *HTTPBin) HTML(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, assets.MustLoad("moby.html"), http.StatusOK)
}

// Robots renders a basic robots.txt file
func (h *HTTPBin) Robots(w http.ResponseWriter, r *http.Request) {
	robotsTxt := []byte(`User-agent: *
Disallow: /deny
`)
	writeResponse(w, http.StatusOK, "text/plain", robotsTxt)
}

// Deny renders a basic page that robots should never access
func (h *HTTPBin) Deny(w http.ResponseWriter, r *http.Request) {
	writeResponse(w, http.StatusOK, "text/plain", []byte(`YOU SHOULDN'T BE HERE`))
}

// Cache returns a 304 if an If-Modified-Since or an If-None-Match header is
// present, otherwise returns the same response as Get.
func (h *HTTPBin) Cache(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("If-Modified-Since") != "" || r.Header.Get("If-None-Match") != "" {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	lastModified := time.Now().Format(time.RFC1123)
	w.Header().Add("Last-Modified", lastModified)
	w.Header().Add("ETag", sha1hash(lastModified))
	h.Get(w, r)
}

// CacheControl sets a Cache-Control header for N seconds for /cache/N requests
func (h *HTTPBin) CacheControl(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	

	seconds, err := strconv.ParseInt(params.ByName("seconds"), 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Add("Cache-Control", fmt.Sprintf("public, max-age=%d", seconds))
	h.Get(w, r)
}

// ETag assumes the resource has the given etag and response to If-None-Match
// and If-Match headers appropriately.
func (h *HTTPBin) ETag(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	etag := params.ByName("etag")
	w.Header().Set("ETag", fmt.Sprintf(`"%s"`, etag))

	// TODO: This mostly duplicates the work of Get() above, should this be
	// pulled into a little helper?
	resp := &getResponse{
		Args:    r.URL.Query(),
		Headers: getRequestHeaders(r),
		Origin:  getOrigin(r),
		URL:     getURL(r).String(),
	}
	body, _ := json.Marshal(resp)

	// Let http.ServeContent deal with If-None-Match and If-Match headers:
	// https://golang.org/pkg/net/http/#ServeContent
	http.ServeContent(w, r, "response.json", time.Now(), bytes.NewReader(body))
}

// Bytes returns N random bytes generated with an optional seed
func (h *HTTPBin) Bytes(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	handleBytes(w, r, false,params)
}

// StreamBytes streams N random bytes generated with an optional seed in chunks
// of a given size.
func (h *HTTPBin) StreamBytes(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	handleBytes(w, r, true,params)
}

// handleBytes consolidates the logic for validating input params of the Bytes
// and StreamBytes endpoints and knows how to write the response in chunks if
// streaming is true.
func handleBytes(w http.ResponseWriter, r *http.Request, streaming bool, params httprouter.Params) {

	numBytes, err := strconv.Atoi(params.ByName("numBytes"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if numBytes < 1 {
		numBytes = 1
	} else if numBytes > 100*1024 {
		numBytes = 100 * 1024
	}

	var chunkSize int
	var write func([]byte)

	if streaming {
		if r.URL.Query().Get("chunk_size") != "" {
			chunkSize, err = strconv.Atoi(r.URL.Query().Get("chunk_size"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			chunkSize = 10 * 1024
		}

		write = func() func(chunk []byte) {
			f := w.(http.Flusher)
			return func(chunk []byte) {
				w.Write(chunk)
				f.Flush()
			}
		}()
	} else {
		chunkSize = numBytes
		write = func(chunk []byte) {
			w.Header().Set("Content-Length", strconv.Itoa(len(chunk)))
			w.Write(chunk)
		}
	}

	var seed int64
	rawSeed := r.URL.Query().Get("seed")
	if rawSeed != "" {
		seed, err = strconv.ParseInt(rawSeed, 10, 64)
		if err != nil {
			http.Error(w, "invalid seed", http.StatusBadRequest)
			return
		}
	} else {
		seed = time.Now().Unix()
	}

	src := rand.NewSource(seed)
	rng := rand.New(src)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	var chunk []byte
	for i := 0; i < numBytes; i++ {
		chunk = append(chunk, byte(rng.Intn(256)))
		if len(chunk) == chunkSize {
			write(chunk)
			chunk = nil
		}
	}
	if len(chunk) > 0 {
		write(chunk)
	}
}

// Links redirects to the first page in a series of N links
func (h *HTTPBin) Links(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	n, err := strconv.Atoi(params.ByName("n"))
	if err != nil || n < 0 || n > 256 {
		http.Error(w, "Invalid link count", http.StatusBadRequest)
		return
	}

	// Are we handling /links/<n>/<offset>? If so, render an HTML page
	offset:=params.ByName("offset")
	if offset!="" {
		offset, err := strconv.Atoi(offset)
		if err != nil {
			http.Error(w, "Invalid offset", http.StatusBadRequest)
		}
		doLinksPage(w, r, n, offset)
		return
	}

	// Otherwise, redirect from /links/<n> to /links/<n>/0
	r.URL.Path = r.URL.Path + "/0"
	w.Header().Set("Location", r.URL.String())
	w.WriteHeader(http.StatusFound)
}

// doLinksPage renders a page with a series of N links
func doLinksPage(w http.ResponseWriter, r *http.Request, n int, offset int) {
	w.Header().Add("Content-Type", htmlContentType)
	w.WriteHeader(http.StatusOK)

	w.Write([]byte("<html><head><title>Links</title></head><body>"))
	for i := 0; i < n; i++ {
		if i == offset {
			fmt.Fprintf(w, "%d ", i)
		} else {
			fmt.Fprintf(w, `<a href="/links/%d/%d">%d</a> `, n, i, i)
		}
	}
	w.Write([]byte("</body></html>"))
}

// ImageAccept responds with an appropriate image based on the Accept header
func (h *HTTPBin) ImageAccept(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	if accept == "" || strings.Contains(accept, "image/png") || strings.Contains(accept, "image/*") {
		doImage(w, "png")
	} else if strings.Contains(accept, "image/webp") {
		doImage(w, "webp")
	} else if strings.Contains(accept, "image/svg+xml") {
		doImage(w, "svg")
	} else if strings.Contains(accept, "image/jpeg") {
		doImage(w, "jpeg")
	} else {
		http.Error(w, "Unsupported media type", http.StatusUnsupportedMediaType)
	}
}

// Image responds with an image of a specific kind, from /image/<kind>
func (h *HTTPBin) Image(w http.ResponseWriter, r *http.Request,params httprouter.Params) {
	/*
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	*/
	doImage(w, params.ByName("kind"))
}

// doImage responds with a specific kind of image, if there is an image asset
// of the given kind.
func doImage(w http.ResponseWriter, kind string) {
	img, err := assets.Load("image." + kind)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
	}
	contentType := "image/" + kind
	if kind == "svg" {
		contentType = "image/svg+xml"
	}
	writeResponse(w, http.StatusOK, contentType, img)
}

// XML responds with an XML document
func (h *HTTPBin) XML(w http.ResponseWriter, r *http.Request) {
	writeResponse(w, http.StatusOK, "application/xml", assets.MustLoad("sample.xml"))
}

// DigestAuth handles a simple implementation of HTTP Digest Authentication,
// which supports the "auth" QOP and the MD5 and SHA-256 crypto algorithms.
//
// /digest-auth/<qop>/<user>/<passwd>
// /digest-auth/<qop>/<user>/<passwd>/<algorithm>
func (h *HTTPBin) DigestAuth(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	/*
		parts := strings.Split(r.URL.Path, "/")
		count := len(parts)

		if count != 5 && count != 6 {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	*/
	qop := strings.ToLower(params.ByName("qop"))
	user := params.ByName("user")
	password := params.ByName("passwd")

	algoName := params.ByName("algorithm")
	if algoName == "" {
		algoName = "MD5"
	}

	if qop != "auth" {
		http.Error(w, "Invalid QOP directive", http.StatusBadRequest)
		return
	}
	if algoName != "MD5" && algoName != "SHA-256" {
		http.Error(w, "Invalid algorithm", http.StatusBadRequest)
		return
	}

	algorithm := digest.MD5
	if algoName == "SHA-256" {
		algorithm = digest.SHA256
	}

	if !digest.Check(r, user, password) {
		w.Header().Set("WWW-Authenticate", digest.Challenge("go-httpbin", algorithm))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	resp, _ := json.Marshal(&authResponse{
		Authorized: true,
		User:       user,
	})
	writeJSON(w, resp, http.StatusOK)
}

// UUID - responds with a generated UUID
func (h *HTTPBin) UUID(w http.ResponseWriter, r *http.Request) {
	resp, _ := json.Marshal(&uuidResponse{
		UUID: uuidv4(),
	})
	writeJSON(w, resp, http.StatusOK)
}

// Base64 - encodes/decodes input data
func (h *HTTPBin) Base64(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	//up to two params in the URL
	mode,data:=params.ByName("arg1"),params.ByName("arg2")

	
	if data=="" {
		data=mode
		mode=""
	}

	if len(params)>2 || r.URL.Path[len(r.URL.Path)-1]=='/' {
		http.Error(w, "invalid URL\n", http.StatusBadRequest)
		return
	}

	b, err := newBase64Helper(mode,data)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusBadRequest)
		return
	}

	var result []byte
	var base64Error error

	if b.operation == "decode" {
		result, base64Error = b.Decode()
	} else {
		result, base64Error = b.Encode()
	}

	if base64Error != nil {
		http.Error(w, fmt.Sprintf("%s failed: %s", b.operation, base64Error), http.StatusBadRequest)
		return
	}
	writeResponse(w, http.StatusOK, "text/html", result)
}

// JSON - returns a sample json
func (h *HTTPBin) JSON(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, assets.MustLoad("sample.json"), http.StatusOK)
}

// Bearer - Prompts the user for authorization using bearer authentication.
func (h *HTTPBin) Bearer(w http.ResponseWriter, r *http.Request) {
	reqToken := r.Header.Get("Authorization")
	tokenFields := strings.Fields(reqToken)
	if len(tokenFields) != 2 || tokenFields[0] != "Bearer" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, _ := json.Marshal(&bearerResponse{
		Authenticated: true,
		Token:         tokenFields[1],
	})
	writeJSON(w, body, http.StatusOK)
}
