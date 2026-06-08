package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/chrismeyersfsu/safe-secret/internal/audit"
	"github.com/chrismeyersfsu/safe-secret/internal/placeholder"
	"github.com/chrismeyersfsu/safe-secret/internal/scrubber"
	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
	"github.com/elazarl/goproxy"
	"github.com/google/uuid"
)

type ProxyServer struct {
	proxy       *goproxy.ProxyHttpServer
	store       secrets.SecretStore
	audit       *audit.Logger
	certCache   *CertCache
	mitmHosts   map[string]bool
	maxIdleConn int
}

type injectedSecrets struct {
	secrets [][]byte
}

func NewProxyServer(store secrets.SecretStore, caCert *tls.Certificate, auditLog *audit.Logger, maxIdleConnsPerHost int) *ProxyServer {
	proxy := goproxy.NewProxyHttpServer()
	certCache := NewCertCache(caCert)

	// Build MITM host set from store
	mitmHosts := make(map[string]bool)
	for _, host := range store.AllHosts() {
		mitmHosts[host] = true
	}

	ps := &ProxyServer{
		proxy:       proxy,
		store:       store,
		audit:       auditLog,
		certCache:   certCache,
		mitmHosts:   mitmHosts,
		maxIdleConn: maxIdleConnsPerHost,
	}

	// Set cert cache on proxy for MITM certificate caching
	proxy.CertStore = certCache

	// Set up cert cache for MITM
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(ps.handleConnect))

	// Set up request handler for MITM'd requests
	proxy.OnRequest().DoFunc(ps.handleRequest)

	// Set up response handler
	proxy.OnResponse().DoFunc(ps.handleResponse)

	// Configure transport
	if proxy.Tr != nil {
		proxy.Tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	}

	return ps
}

func (ps *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ps.proxy.ServeHTTP(w, r)
}

func (ps *ProxyServer) handleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	// Check if this host should be MITM'd
	if ps.mitmHosts[host] {
		return goproxy.MitmConnect, host
	}

	// Tunnel non-MITM hosts
	ps.audit.Tunnel(host)
	return goproxy.OkConnect, host
}

func (ps *ProxyServer) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	reqID := uuid.New().String()
	ctx.UserData = map[string]interface{}{"req_id": reqID}

	// Read request body
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}

	// Scan for placeholders
	matches := placeholder.Scan(bodyBytes)
	if len(matches) == 0 {
		// No placeholders, restore body and continue
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return r, nil
	}

	// Build lookup function
	dstHost := r.URL.Host
	if dstHost == "" {
		dstHost = r.Host
	}

	var injected [][]byte
	lookupFunc := func(qualifier, identifier string) ([]byte, []string, error) {
		var entry *secrets.SecretEntry
		var err error

		if qualifier == "NAME" {
			entry, err = ps.store.LookupByName(identifier)
		} else {
			entry, err = ps.store.LookupByID(identifier)
		}

		if err != nil {
			return nil, nil, err
		}

		return entry.Value, entry.AllowedHosts, nil
	}

	// Replace placeholders
	replacedBody, results := placeholder.Replace(bodyBytes, dstHost, lookupFunc)

	// Audit log results
	for _, result := range results {
		placeholderStr := fmt.Sprintf("__SAFE_SECRET__%s__%s", result.Qualifier, result.Identifier)
		lookupKey := fmt.Sprintf("%s:%s", result.Qualifier, result.Identifier)

		if result.Replaced {
			ps.audit.SecretInjected(reqID, lookupKey, placeholderStr, dstHost, r.URL.Path, r.Method)
			// Get the actual secret value to track for scrubbing
			var entry *secrets.SecretEntry
			if result.Qualifier == "NAME" {
				entry, _ = ps.store.LookupByName(result.Identifier)
			} else {
				entry, _ = ps.store.LookupByID(result.Identifier)
			}
			if entry != nil {
				injected = append(injected, entry.Value)
			}
		} else if result.Reason == "not_found" {
			ps.audit.SecretNotFound(reqID, lookupKey, placeholderStr, dstHost, r.URL.Path, r.Method)
		} else if result.Reason == "host_blocked" {
			ps.audit.HostBlocked(reqID, lookupKey, placeholderStr, dstHost, r.URL.Path, r.Method)
		}
	}

	// Store injected secrets in context for response scrubbing
	if len(injected) > 0 {
		userData := ctx.UserData.(map[string]interface{})
		userData["injected"] = &injectedSecrets{secrets: injected}
	}

	// Update request body
	r.Body = io.NopCloser(bytes.NewReader(replacedBody))
	r.ContentLength = int64(len(replacedBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(replacedBody)))

	return r, nil
}

func (ps *ProxyServer) handleResponse(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if r == nil || ctx.UserData == nil {
		return r
	}

	userData, ok := ctx.UserData.(map[string]interface{})
	if !ok {
		return r
	}

	reqID, _ := userData["req_id"].(string)
	injectedData, hasInjected := userData["injected"].(*injectedSecrets)

	// Only scrub if we injected secrets
	if !hasInjected || injectedData == nil || len(injectedData.secrets) == 0 {
		return r
	}

	// Read response body
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		// Can't read body, return as-is
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return r
	}

	// Build scrubber
	scrub := scrubber.New(injectedData.secrets)
	scrubbedBody, results := scrub.Scrub(bodyBytes)

	// Audit log scrubbing
	dstHost := r.Request.URL.Host
	if dstHost == "" {
		dstHost = r.Request.Host
	}

	totalScrubbed := 0
	for _, result := range results {
		totalScrubbed += result.Count
	}

	if totalScrubbed > 0 {
		ps.audit.ScrubHit(reqID, dstHost, r.Request.URL.Path, r.Request.Method, totalScrubbed)
	}

	// Update response body and content length
	r.Body = io.NopCloser(bytes.NewReader(scrubbedBody))
	r.ContentLength = int64(len(scrubbedBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(scrubbedBody)))

	return r
}

type CertCache struct {
	ca    *tls.Certificate
	cache sync.Map
}

func NewCertCache(ca *tls.Certificate) *CertCache {
	return &CertCache{
		ca: ca,
	}
}

// Fetch implements goproxy.CertStorage interface
func (c *CertCache) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	// Check cache
	if cert, ok := c.cache.Load(hostname); ok {
		return cert.(*tls.Certificate), nil
	}

	// Generate new cert using our MITM cert generator
	cert, err := GenerateMITMCert(hostname, c.ca)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.cache.Store(hostname, cert)
	return cert, nil
}
