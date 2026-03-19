package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// ---------------------------------------------------------------------------
// ProxyHandler
// ---------------------------------------------------------------------------

// ProxyHandler is an http.Handler that:
//  1. Walks the ordered RouteRule list and finds the first rule whose Prefix
//     is a prefix of the request path.
//  2. Rewrites the request to target+path, injects the configured upstream
//     Bearer token (if any), and reverse-proxies the request.
//  3. Strips the Authorization header from the upstream response so it is
//     never forwarded back to the client.
//  4. Returns 502 Bad Gateway if no rule matches (should not happen when a
//     catch-all "/" rule is present).
type ProxyHandler struct {
	rules   []RouteRule
	proxies map[string]*httputil.ReverseProxy // routeKey → pre-built proxy
}

// routeKey returns a map key that uniquely identifies a (target, token) pair.
// Two rules with the same target but different tokens need separate proxies
// because each proxy has a different director closure.
func routeKey(r RouteRule) string {
	return r.Target + "\x00" + r.UpstreamToken
}

// NewProxyHandler validates the route table and pre-builds one
// httputil.ReverseProxy per unique (target, upstream_token) combination for
// connection reuse.
func NewProxyHandler(rules []RouteRule) (*ProxyHandler, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("proxy: route table is empty")
	}

	proxies := make(map[string]*httputil.ReverseProxy)
	for _, r := range rules {
		key := routeKey(r)
		if _, exists := proxies[key]; exists {
			continue // already created for this (target, token) pair
		}
		targetURL, err := url.Parse(r.Target)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid target %q: %w", r.Target, err)
		}
		rp := httputil.NewSingleHostReverseProxy(targetURL)
		rp.Director = makeDirector(targetURL, r.UpstreamToken)
		// Strip Authorization from upstream responses so it never reaches the client.
		rp.ModifyResponse = stripUpstreamAuthHeader
		proxies[key] = rp
	}

	return &ProxyHandler{rules: rules, proxies: proxies}, nil
}

// ServeHTTP satisfies http.Handler.
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, rule := range p.rules {
		if strings.HasPrefix(r.URL.Path, rule.Prefix) {
			p.proxies[routeKey(rule)].ServeHTTP(w, r)
			return
		}
	}
	http.Error(w, "no matching route", http.StatusBadGateway)
}

// ---------------------------------------------------------------------------
// Director & response modifier
// ---------------------------------------------------------------------------

// makeDirector returns a director function that:
//   - Rewrites scheme and host to targetURL.
//   - Removes the client-facing auth headers (X-Launcher-Signature,
//     Authorization) from the outgoing request.
//   - If upstreamToken is non-empty, sets Authorization: Bearer <token> on
//     the outgoing request so the upstream receives its own credential.
func makeDirector(targetURL *url.URL, upstreamToken string) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host

		// Remove client-facing auth headers — they must not reach the upstream.
		req.Header.Del("X-Launcher-Signature")
		req.Header.Del("Authorization")

		// Inject the pre-configured upstream token if provided.
		if upstreamToken != "" {
			req.Header.Set("Authorization", "Bearer "+upstreamToken)
		}

		// Add a forwarding hint so the upstream knows the original host.
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
	}
}

// stripUpstreamAuthHeader removes the Authorization header from any response
// returned by the upstream before it is forwarded to the client.  This
// prevents the upstream token from leaking back to the caller.
func stripUpstreamAuthHeader(resp *http.Response) error {
	resp.Header.Del("Authorization")
	return nil
}
