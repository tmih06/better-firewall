// Package protect wires optional upstream threat-intelligence sources into
// bfirewall. This file implements the native CrowdSec Local API (LAPI)
// bouncer client; the verified wire contract lives in
// docs/crowdsec-lapi-research.md.
package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// crowdsecHTTPTimeout bounds one stream request including the body read.
// Polls run on an interval, so a hung LAPI must fail before the next tick.
const crowdsecHTTPTimeout = 30 * time.Second

// crowdsecKeyFileMaxBytes bounds the API key file; cscli-issued bouncer
// keys are ~64 hex characters, so anything larger is misconfiguration.
const crowdsecKeyFileMaxBytes = 64 << 10

// crowdsecErrBodyBytes bounds the error-body excerpt read on non-200.
const crowdsecErrBodyBytes = 8 << 10

// crowdsecMaxBodyBytes bounds one stream response body. A startup snapshot
// can hold tens of thousands of decisions (~200 bytes each); 64 MiB is far
// above that while still bounding a malformed or hostile endpoint. It is a
// var so tests can shrink it.
var crowdsecMaxBodyBytes int64 = 64 << 20

// errCrowdSecRedirect rejects redirects inside the HTTP client. The Go
// client re-sends custom headers such as X-Api-Key to the redirect target,
// so following any redirect could leak the bouncer key off the LAPI host.
var errCrowdSecRedirect = errors.New("refusing to follow redirect")

// CrowdSecClient polls a CrowdSec LAPI decisions stream as a bouncer.
// Construct it with NewCrowdSecClient; it is safe for concurrent use, though
// callers should serialize polls so the server-side delta cursor stays
// meaningful.
type CrowdSecClient struct {
	base       *url.URL
	apiKey     string
	userAgent  string
	httpClient *http.Client
}

// NewCrowdSecClient validates cfg and reads the bouncer API key.
//
// cfg.URL must use https, or http only when it targets a loopback address
// (127.0.0.0/8, ::1, localhost): the API key travels as a plain header, so
// cleartext anywhere else would expose it. cfg.APIKeyFile must be a regular
// file with no group/other permission bits holding a non-empty key.
// cfg.PollInterval is left to the caller driving Stream.
func NewCrowdSecClient(cfg CrowdSecConfig, version string) (*CrowdSecClient, error) {
	base, err := parseCrowdSecURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	key, err := readCrowdSecKey(cfg.APIKeyFile)
	if err != nil {
		return nil, err
	}
	version = strings.TrimSpace(version)
	if version == "" {
		version = "dev"
	}
	return &CrowdSecClient{
		base:      base,
		apiKey:    key,
		userAgent: "bfirewall/" + version,
		httpClient: &http.Client{
			Timeout: crowdsecHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errCrowdSecRedirect
			},
		},
	}, nil
}

// Stream performs one GET /v1/decisions/stream poll scoped to ip,range
// decisions. With startup=true the server returns the full active set in New
// plus historical deletions in Deleted (for restart reconciliation); with
// startup=false it returns only the delta since this bouncer key's last
// successful pull. Either list may be nil: LAPI emits null for empty lists.
// The request honors ctx and is additionally bounded by the client's own
// timeout.
func (c *CrowdSecClient) Stream(ctx context.Context, startup bool) (CrowdSecResponse, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/decisions/stream"
	u.RawPath = ""
	u.Fragment = ""
	q := u.Query()
	q.Set("scopes", "ip,range")
	if startup {
		q.Set("startup", "true")
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: building stream request: %w", err)
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: stream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CrowdSecResponse{}, c.statusError(resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, crowdsecMaxBodyBytes+1))
	if err != nil {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: reading stream response: %w", err)
	}
	if int64(len(body)) > crowdsecMaxBodyBytes {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: stream response exceeds %d byte limit", crowdsecMaxBodyBytes)
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: decoding stream response: expected a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: decoding stream response: %w", err)
	}
	newRaw, hasNew := fields["new"]
	deletedRaw, hasDeleted := fields["deleted"]
	if !hasNew || !hasDeleted {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: decoding stream response: missing new or deleted list")
	}
	var out CrowdSecResponse
	if err := json.Unmarshal(newRaw, &out.New); err != nil {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: decoding new decisions: %w", err)
	}
	if err := json.Unmarshal(deletedRaw, &out.Deleted); err != nil {
		return CrowdSecResponse{}, fmt.Errorf("crowdsec: decoding deleted decisions: %w", err)
	}
	return out, nil
}

// statusError renders a non-200 LAPI reply, surfacing the server's
// {"message": ...} when present. The API key is redacted from the echoed
// message defensively so a hostile endpoint cannot smuggle it into logs.
func (c *CrowdSecClient) statusError(resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, crowdsecErrBodyBytes+1))
	var parsed struct {
		Message string `json:"message"`
	}
	detail := ""
	if json.Unmarshal(snippet, &parsed) == nil && parsed.Message != "" {
		detail = ": " + strings.ReplaceAll(parsed.Message, c.apiKey, "<redacted>")
	}
	hint := ""
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		hint = "; check the bouncer API key (cscli bouncers list on the LAPI host)"
	}
	return fmt.Errorf("crowdsec: LAPI returned %s%s%s", resp.Status, detail, hint)
}

// parseCrowdSecURL validates the configured LAPI base URL.
func parseCrowdSecURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("crowdsec: invalid url %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https", "http":
	default:
		return nil, fmt.Errorf("crowdsec: url %q has unsupported scheme %q (want https, or http on loopback)", raw, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("crowdsec: url %q has no host", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("crowdsec: url %q must not embed credentials", raw)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("crowdsec: url %q uses http to a non-loopback host; use https, or keep LAPI on loopback", raw)
	}
	return u, nil
}

// isLoopbackHost reports whether host is a loopback IP literal or the
// reserved "localhost" name. Subdomains of localhost are deliberately not
// trusted: their resolution is not guaranteed to stay on the machine.
func isLoopbackHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

// readCrowdSecKey loads the bouncer API key. The file holds a shared secret,
// so permissive modes are refused rather than trusting a key other local
// users can read. The key itself never appears in errors.
func readCrowdSecKey(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("crowdsec: api_key_file is required")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("crowdsec: cannot stat api key file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("crowdsec: api key file %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("crowdsec: api key file %s is accessible by group/other (mode %04o); restrict it with chmod 600", path, perm)
	}
	if fi.Size() == 0 {
		return "", fmt.Errorf("crowdsec: api key file %s is empty", path)
	}
	if fi.Size() > crowdsecKeyFileMaxBytes {
		return "", fmt.Errorf("crowdsec: api key file %s is %d bytes; a bouncer key is ~64 characters", path, fi.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("crowdsec: cannot read api key file %s: %w", path, err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("crowdsec: api key file %s contains only whitespace", path)
	}
	return key, nil
}
