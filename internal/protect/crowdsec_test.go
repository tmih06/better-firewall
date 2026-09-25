package protect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKeyFile materializes an API key file with an exact mode (umask-proof).
func writeKeyFile(t *testing.T, dir, contents string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "lapi.key")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod key file: %v", err)
	}
	return path
}

// newClient builds a client against srv.URL with a valid key file.
func newClient(t *testing.T, srv *httptest.Server) *CrowdSecClient {
	t.Helper()
	key := writeKeyFile(t, t.TempDir(), "test-bouncer-key\n", 0o600)
	c, err := NewCrowdSecClient(CrowdSecConfig{URL: srv.URL, APIKeyFile: key}, "1.2.3")
	if err != nil {
		t.Fatalf("NewCrowdSecClient: %v", err)
	}
	return c
}

func TestStreamStartupSendsContractAndHeaders(t *testing.T) {
	var gotPath, gotQuery, gotKey, gotUA, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotKey = r.Header.Get("X-Api-Key")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"new":[{"id":1001,"uuid":"u-1","origin":"CAPI","type":"ban","scope":"Ip","value":"1.2.3.4","duration":"3h59m57.64s","scenario":"crowdsecurity/http-probing"}],"deleted":null}`)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	out, err := c.Stream(context.Background(), true)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if gotPath != "/v1/decisions/stream" {
		t.Errorf("path = %q, want /v1/decisions/stream", gotPath)
	}
	if !strings.Contains(gotQuery, "startup=true") {
		t.Errorf("query %q missing startup=true", gotQuery)
	}
	if !strings.Contains(gotQuery, "scopes=ip%2Crange") {
		t.Errorf("query %q missing scopes=ip,range", gotQuery)
	}
	if gotKey != "test-bouncer-key" {
		t.Errorf("X-Api-Key = %q", gotKey)
	}
	if gotUA != "bfirewall/1.2.3" {
		t.Errorf("User-Agent = %q, want bfirewall/1.2.3", gotUA)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if len(out.New) != 1 || len(out.Deleted) != 0 {
		t.Fatalf("response = %+v", out)
	}
	d := out.New[0]
	if d.ID != 1001 || d.Type != "ban" || d.Scope != "Ip" ||
		d.Value != "1.2.3.4" || d.Duration != "3h59m57.64s" ||
		d.Scenario != "crowdsecurity/http-probing" {
		t.Errorf("decision = %+v", d)
	}
}

func TestStreamDeltaOmitsStartupAndParsesNulls(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		// LAPI emits null for empty lists; keep it.
		fmt.Fprint(w, `{"new":null,"deleted":[{"id":7,"type":"ban","scope":"Range","value":"2.2.3.0/24","duration":"-18897h25m52.8s","scenario":"crowdsecurity/http-probing"}]}`)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	out, err := c.Stream(context.Background(), false)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if strings.Contains(gotQuery, "startup") {
		t.Errorf("delta query %q must not carry startup", gotQuery)
	}
	if !strings.Contains(gotQuery, "scopes=ip%2Crange") {
		t.Errorf("query %q missing scopes=ip,range", gotQuery)
	}
	if len(out.New) != 0 {
		t.Errorf("New = %+v, want empty (JSON null)", out.New)
	}
	if len(out.Deleted) != 1 || out.Deleted[0].Duration != "-18897h25m52.8s" {
		t.Errorf("Deleted = %+v; negative duration must survive as a string", out.Deleted)
	}
}

func TestStreamChunkedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher) // httptest writers always flush
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"new":[{"id":1,"type":"ban","scope":"ip","value":"9.9.9.9","duration":"4h0m0s","scenario":"s"}`)
		flusher.Flush() // commit headers; remaining writes go out chunked
		fmt.Fprint(w, `,{"id":2,"type":"ban","scope":"ip","value":"8.8.8.8/32","duration":"1m0s","scenario":"s"}],"deleted":[]}`)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	out, err := c.Stream(context.Background(), true)
	if err != nil {
		t.Fatalf("Stream on chunked body: %v", err)
	}
	if len(out.New) != 2 || out.New[1].Value != "8.8.8.8/32" {
		t.Fatalf("New = %+v", out.New)
	}
}

func TestStreamStatusErrors(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantSubstr []string
	}{
		{"forbidden with message", 403, `{"message":"access forbidden"}`, []string{"403", "access forbidden", "API key"}},
		{"unauthorized empty body", 401, ``, []string{"401"}},
		{"server error message", 500, `{"message":"QueryFail: invalid filter"}`, []string{"500", "QueryFail"}},
		{"teapot non-json body", 418, `<html>nope</html>`, []string{"418"}},
		{"redaction", 403, `{"message":"key test-bouncer-key rejected"}`, []string{"<redacted>"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			c := newClient(t, srv)
			_, err := c.Stream(context.Background(), false)
			if err == nil {
				t.Fatalf("status %d: Stream succeeded", tc.status)
			}
			for _, s := range tc.wantSubstr {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("error %q missing %q", err, s)
				}
			}
			// The API key must never leak into errors, even when the
			// server echoes it back.
			if strings.Contains(err.Error(), "test-bouncer-key") {
				t.Errorf("error leaks API key: %q", err)
			}
		})
	}
}

func TestStreamRedirectDoesNotForwardKey(t *testing.T) {
	var sawKey bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" {
			sawKey = true
		}
		fmt.Fprint(w, `{"new":[],"deleted":[]}`)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/decisions/stream", http.StatusFound)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	_, err := c.Stream(context.Background(), false)
	if err == nil {
		t.Fatal("Stream followed redirect")
	}
	if !errors.Is(err, errCrowdSecRedirect) {
		t.Errorf("error %v is not the redirect refusal", err)
	}
	if sawKey {
		t.Error("API key was forwarded to the redirect target")
	}
}

func TestNewClientRejectsUnsafeURLs(t *testing.T) {
	key := writeKeyFile(t, t.TempDir(), "k\n", 0o600)
	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"no scheme", "127.0.0.1:8080"},
		{"bad scheme", "ftp://127.0.0.1/lapi"},
		{"no host", "http://"},
		{"http remote IP", "http://10.0.0.5:8080"},
		{"http remote name", "http://lapi.internal:8080"},
		{"http localhost subdomain", "http://evil.localhost:8080"},
		{"embedded credentials", "https://user:pw@127.0.0.1:8080"},
		{"garbage", "http://127.0.0.1:abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCrowdSecClient(CrowdSecConfig{URL: tc.url, APIKeyFile: key}, "1"); err == nil {
				t.Errorf("URL %q accepted", tc.url)
			}
		})
	}
}

func TestNewClientAcceptsLoopbackHTTPAndHTTPS(t *testing.T) {
	key := writeKeyFile(t, t.TempDir(), "k\n", 0o600)
	for _, u := range []string{
		"http://127.0.0.1:8080", "http://localhost:8080", "http://LOCALHOST",
		"http://[::1]:8080", "http://127.42.0.1", "https://lapi.example.com",
		"https://192.0.2.1:8443/lapi",
	} {
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: u, APIKeyFile: key}, "1"); err != nil {
			t.Errorf("URL %q rejected: %v", u, err)
		}
	}
}

func TestNewClientRejectsBadKeyFiles(t *testing.T) {
	dir := t.TempDir()
	goodURL := "https://lapi.example.com"
	t.Run("missing path", func(t *testing.T) {
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL, APIKeyFile: filepath.Join(dir, "absent")}, "1"); err == nil {
			t.Error("missing key file accepted")
		}
	})
	t.Run("empty path", func(t *testing.T) {
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL}, "1"); err == nil {
			t.Error("empty api_key_file accepted")
		}
	})
	t.Run("empty file", func(t *testing.T) {
		p := writeKeyFile(t, dir, "", 0o600)
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL, APIKeyFile: p}, "1"); err == nil {
			t.Error("empty key file accepted")
		}
	})
	t.Run("whitespace only", func(t *testing.T) {
		p := writeKeyFile(t, dir, "  \n\t", 0o600)
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL, APIKeyFile: p}, "1"); err == nil {
			t.Error("whitespace key file accepted")
		}
	})
	for _, perm := range []os.FileMode{0o640, 0o644, 0o604, 0o777} {
		t.Run(fmt.Sprintf("insecure mode %04o", perm), func(t *testing.T) {
			p := writeKeyFile(t, dir, "k\n", perm)
			if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL, APIKeyFile: p}, "1"); err == nil {
				t.Errorf("mode %04o key file accepted", perm)
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL, APIKeyFile: dir}, "1"); err == nil {
			t.Error("directory accepted as key file")
		}
	})
	t.Run("owner-restricted ok", func(t *testing.T) {
		p := writeKeyFile(t, dir, "k\n", 0o400)
		if _, err := NewCrowdSecClient(CrowdSecConfig{URL: goodURL, APIKeyFile: p}, "1"); err != nil {
			t.Errorf("mode 0400 rejected: %v", err)
		}
	})
}

func TestStreamOversizedResponse(t *testing.T) {
	old := crowdsecMaxBodyBytes
	crowdsecMaxBodyBytes = 512
	defer func() { crowdsecMaxBodyBytes = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"new":[`+strings.Repeat(" ", 1024)+`],"deleted":[]}`)
	}))
	defer srv.Close()

	c := newClient(t, srv)
	if _, err := c.Stream(context.Background(), false); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized body error = %v", err)
	}
}

func TestStreamMalformedJSON(t *testing.T) {
	for _, body := range []string{`{not json`, `["array-not-object"]`, `"scalar"`, `null`, `{}`, `{"new":[]}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		}))
		c := newClient(t, srv)
		_, err := c.Stream(context.Background(), false)
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "decoding") {
			t.Errorf("body %q: error = %v", body, err)
		}
	}
}

func TestStreamHonorsCanceledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hold until the client cancels
	}))
	defer srv.Close()

	c := newClient(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Stream(ctx, false)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestStreamPreservesBasePathPrefix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"new":[],"deleted":[]}`)
	}))
	defer srv.Close()

	key := writeKeyFile(t, t.TempDir(), "k", 0o600)
	c, err := NewCrowdSecClient(CrowdSecConfig{URL: srv.URL + "/lapi/", APIKeyFile: key}, "1")
	if err != nil {
		t.Fatalf("NewCrowdSecClient: %v", err)
	}
	if _, err := c.Stream(context.Background(), false); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if gotPath != "/lapi/v1/decisions/stream" {
		t.Errorf("path = %q; base path prefix dropped", gotPath)
	}
}

func TestNewClientEmptyVersionFallsBack(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, `{"new":null,"deleted":null}`)
	}))
	defer srv.Close()

	key := writeKeyFile(t, t.TempDir(), "k", 0o600)
	c, err := NewCrowdSecClient(CrowdSecConfig{URL: srv.URL, APIKeyFile: key}, "")
	if err != nil {
		t.Fatalf("NewCrowdSecClient: %v", err)
	}
	if _, err := c.Stream(context.Background(), false); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if gotUA != "bfirewall/dev" {
		t.Errorf("User-Agent = %q, want bfirewall/dev", gotUA)
	}
}

func TestStreamHTTPSURLAccepted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"new":[{"id":3,"type":"ban","scope":"Ip","value":"5.5.5.5","duration":"10m0s","scenario":"s"}],"deleted":null}`)
	}))
	defer srv.Close()

	key := writeKeyFile(t, t.TempDir(), "tls-key", 0o600)
	c, err := NewCrowdSecClient(CrowdSecConfig{URL: srv.URL, APIKeyFile: key}, "1")
	if err != nil {
		t.Fatalf("NewCrowdSecClient: %v", err)
	}
	// Trust the test CA for this client only; production keeps system roots.
	c.httpClient.Transport = srv.Client().Transport
	out, err := c.Stream(context.Background(), false)
	if err != nil {
		t.Fatalf("Stream over https: %v", err)
	}
	if len(out.New) != 1 || out.New[0].Value != "5.5.5.5" {
		t.Fatalf("New = %+v", out.New)
	}
}
