package goclilogin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"
)

const (
	serviceClientID = "prod-svc-scheduler"
	serviceSecret   = "s3cret"
)

// serviceIDP issues tokens to one confidential client, authenticated by HTTP
// Basic. Like Authelia, it grants only the scopes a request names and answers
// one the client does not hold, openid included, with 400 invalid_scope. A
// non-zero failWith answers the token request with failBody in the provider's
// place, the way a proxy in front of it would.
type serviceIDP struct {
	server    *httptest.Server
	held      map[string]bool
	expiresIn int
	failWith  int
	failBody  string

	mu          sync.Mutex
	discoveries int
	requests    int
	scopes      []string
}

func newServiceIDP(t *testing.T, expiresIn int) *serviceIDP {
	t.Helper()
	idp := &serviceIDP{
		held:      map[string]bool{"prod.items.read": true, "prod.items.write": true},
		expiresIn: expiresIn,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		idp.mu.Lock()
		idp.discoveries++
		idp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         idp.server.URL,
			"token_endpoint": idp.server.URL + "/token",
		})
	})
	mux.HandleFunc("/token", idp.token)
	mux.HandleFunc("/resource", func(http.ResponseWriter, *http.Request) {})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (s *serviceIDP) client(scopes ...string) ServiceClient {
	return ServiceClient{Issuer: s.server.URL, ClientID: serviceClientID, Scopes: scopes}
}

func (s *serviceIDP) token(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()
	id, secret, basic := req.BasicAuth()
	requested := strings.Fields(req.PostForm.Get("scope"))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	s.scopes = append(s.scopes, req.PostForm.Get("scope"))

	if s.failWith != 0 {
		if strings.HasPrefix(s.failBody, "{") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/html")
		}
		w.WriteHeader(s.failWith)
		_, _ = io.WriteString(w, s.failBody)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	refuse := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": code})
	}
	switch {
	case !basic || id != serviceClientID || secret != serviceSecret || req.PostForm.Get("grant_type") != "client_credentials":
		refuse(http.StatusUnauthorized, "invalid_client")
		return
	case len(requested) == 0:
		refuse(http.StatusBadRequest, "invalid_scope")
		return
	}
	for _, scope := range requested {
		if !s.held[scope] {
			refuse(http.StatusBadRequest, "invalid_scope")
			return
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": fmt.Sprintf("at-%d", s.requests),
		"token_type":   "bearer",
		"expires_in":   s.expiresIn,
		"scope":        strings.Join(requested, " "),
	})
}

func (s *serviceIDP) seen() (discoveries, requests int, scopes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discoveries, s.requests, append([]string(nil), s.scopes...)
}

func TestClientCredentialsTokenSource_AuthenticatesAsTheClientWithItsScopes(t *testing.T) {
	idp := newServiceIDP(t, 3600)
	source, err := ClientCredentialsTokenSource(context.Background(), idp.client("prod.items.read", "prod.items.write"), serviceSecret)
	if err != nil {
		t.Fatalf("ClientCredentialsTokenSource: %v", err)
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "at-1" {
		t.Errorf("access token = %q, want at-1", token.AccessToken)
	}
	if _, _, scopes := idp.seen(); len(scopes) != 1 || scopes[0] != "prod.items.read prod.items.write" {
		t.Errorf("scopes requested = %q, want [prod.items.read prod.items.write]", scopes)
	}
}

// The token arrives already expired, so the count does not depend on how early
// x/oauth2 treats a token as stale. A source that fetched once and kept the
// result would make one request.
func TestClientCredentialsTokenSource_AnExpiredTokenIsRequestedAgain(t *testing.T) {
	idp := newServiceIDP(t, -1)
	source, err := ClientCredentialsTokenSource(context.Background(), idp.client("prod.items.read"), serviceSecret)
	if err != nil {
		t.Fatalf("ClientCredentialsTokenSource: %v", err)
	}
	for range 3 {
		if _, err := source.Token(); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if _, requests, _ := idp.seen(); requests != 3 {
		t.Errorf("token requests = %d, want 3", requests)
	}
}

// A command holds a resource request's error, with the token failure wrapped
// inside it, so each case is classified from that error.
func TestClientCredentialsTokenSource_OnlyARefusalTheProviderStatesIsRejected(t *testing.T) {
	cases := []struct {
		name     string
		secret   string
		scope    string
		failWith int
		failBody string
		want     SessionState
	}{
		{name: "wrong secret", secret: "wrong", scope: "prod.items.read", want: SessionRejected},
		{name: "scope the client does not hold", secret: serviceSecret, scope: "openid", want: SessionRejected},
		{name: "refusal on a 200", secret: serviceSecret, scope: "prod.items.read", failWith: http.StatusOK, failBody: `{"error":"invalid_client"}`, want: SessionRejected},
		{name: "proxy 401 page", secret: serviceSecret, scope: "prod.items.read", failWith: http.StatusUnauthorized, failBody: "<html>401</html>", want: SessionUnverified},
		{name: "proxy 502 page", secret: serviceSecret, scope: "prod.items.read", failWith: http.StatusBadGateway, failBody: "<html>502</html>", want: SessionUnverified},
		{name: "provider 503 with a code", secret: serviceSecret, scope: "prod.items.read", failWith: http.StatusServiceUnavailable, failBody: `{"error":"temporarily_unavailable"}`, want: SessionUnverified},
		{name: "provider 429 with a code", secret: serviceSecret, scope: "prod.items.read", failWith: http.StatusTooManyRequests, failBody: `{"error":"slow_down"}`, want: SessionUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newServiceIDP(t, 3600)
			idp.failWith, idp.failBody = tc.failWith, tc.failBody
			source, err := ClientCredentialsTokenSource(context.Background(), idp.client(tc.scope), tc.secret)
			if err != nil {
				t.Fatalf("ClientCredentialsTokenSource: %v", err)
			}
			response, err := oauth2.NewClient(context.Background(), source).Get(idp.server.URL + "/resource")
			if err == nil {
				_ = response.Body.Close()
				t.Fatal("the resource request succeeded")
			}
			if state, _ := ClassifySession(nil, err); state != tc.want {
				t.Errorf("state = %s, want %s, for: %v", state, tc.want, err)
			}
		})
	}
}

func TestClientCredentialsTokenSource_RefusesAnIncompleteClientBeforeDiscovery(t *testing.T) {
	cases := []struct {
		name   string
		client func(*serviceIDP) ServiceClient
		secret string
	}{
		{name: "no client id", secret: serviceSecret, client: func(s *serviceIDP) ServiceClient {
			return ServiceClient{Issuer: s.server.URL, Scopes: []string{"prod.items.read"}}
		}},
		{name: "no secret", secret: "", client: func(s *serviceIDP) ServiceClient { return s.client("prod.items.read") }},
		{name: "no scopes", secret: serviceSecret, client: func(s *serviceIDP) ServiceClient { return s.client() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newServiceIDP(t, 3600)
			if _, err := ClientCredentialsTokenSource(context.Background(), tc.client(idp), tc.secret); err == nil {
				t.Fatal("the client was accepted")
			}
			if discoveries, _, _ := idp.seen(); discoveries != 0 {
				t.Errorf("discovery requests = %d, want 0", discoveries)
			}
		})
	}
}
