package goclilogin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// serviceIDP issues tokens to one confidential client, authenticated by HTTP
// Basic, and records what each token request carried.
type serviceIDP struct {
	server    *httptest.Server
	clientID  string
	secret    string
	expiresIn int

	mu       sync.Mutex
	requests int
	scopes   []string
	scopeSet []bool
}

func newServiceIDP(t *testing.T, clientID, secret string, expiresIn int) *serviceIDP {
	t.Helper()
	idp := &serviceIDP{clientID: clientID, secret: secret, expiresIn: expiresIn}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         idp.server.URL,
			"token_endpoint": idp.server.URL + "/token",
		})
	})
	mux.HandleFunc("/token", idp.token)
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (s *serviceIDP) token(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()
	id, secret, basic := req.BasicAuth()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	s.scopes = append(s.scopes, req.PostForm.Get("scope"))
	s.scopeSet = append(s.scopeSet, req.PostForm.Has("scope"))

	w.Header().Set("Content-Type", "application/json")
	if !basic || id != s.clientID || secret != s.secret || req.PostForm.Get("grant_type") != "client_credentials" {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": fmt.Sprintf("at-%d", s.requests),
		"token_type":   "bearer",
		"expires_in":   s.expiresIn,
	})
}

func (s *serviceIDP) seen() (requests int, scopes []string, scopeSet []bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, append([]string(nil), s.scopes...), append([]bool(nil), s.scopeSet...)
}

func serviceConfig(issuer string, scopes ...string) Config {
	return Config{Issuer: issuer, ClientID: "prod-cli-scheduler", Scopes: scopes}
}

func TestClientCredentialsTokenSource_AuthenticatesAsTheClientWithItsScope(t *testing.T) {
	idp := newServiceIDP(t, "prod-cli-scheduler", "s3cret", 3600)
	source, err := ClientCredentialsTokenSource(context.Background(), serviceConfig(idp.server.URL, "prod.items.read"), "s3cret")
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
	if _, scopes, _ := idp.seen(); len(scopes) != 1 || scopes[0] != "prod.items.read" {
		t.Errorf("scopes requested = %q, want [prod.items.read]", scopes)
	}
}

// DefaultScopes carries openid and offline_access, which Authelia refuses on a
// client-credentials client. An empty Scopes must request nothing rather than
// fall back to them.
func TestClientCredentialsTokenSource_EmptyScopesRequestsNone(t *testing.T) {
	idp := newServiceIDP(t, "prod-cli-scheduler", "s3cret", 3600)
	source, err := ClientCredentialsTokenSource(context.Background(), serviceConfig(idp.server.URL), "s3cret")
	if err != nil {
		t.Fatalf("ClientCredentialsTokenSource: %v", err)
	}
	if _, err := source.Token(); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if _, scopes, scopeSet := idp.seen(); len(scopeSet) != 1 || scopeSet[0] {
		t.Errorf("scope parameter sent as %q, want it absent", scopes)
	}
}

func TestClientCredentialsTokenSource_ATokenIsNeverUsedPastItsLife(t *testing.T) {
	// x/oauth2 treats a token as expired ten seconds early, so five seconds is
	// already spent and every call must ask again.
	cases := []struct {
		expiresIn    int
		wantRequests int
	}{
		{expiresIn: 3600, wantRequests: 1},
		{expiresIn: 5, wantRequests: 3},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("expires_in=%d", tc.expiresIn), func(t *testing.T) {
			idp := newServiceIDP(t, "prod-cli-scheduler", "s3cret", tc.expiresIn)
			source, err := ClientCredentialsTokenSource(context.Background(), serviceConfig(idp.server.URL, "prod.items.read"), "s3cret")
			if err != nil {
				t.Fatalf("ClientCredentialsTokenSource: %v", err)
			}
			for range 3 {
				if _, err := source.Token(); err != nil {
					t.Fatalf("Token: %v", err)
				}
			}
			if requests, _, _ := idp.seen(); requests != tc.wantRequests {
				t.Errorf("token requests = %d, want %d", requests, tc.wantRequests)
			}
		})
	}
}

func TestClientCredentialsTokenSource_ARefusedSecretIsARejectedSession(t *testing.T) {
	idp := newServiceIDP(t, "prod-cli-scheduler", "s3cret", 3600)
	source, err := ClientCredentialsTokenSource(context.Background(), serviceConfig(idp.server.URL, "prod.items.read"), "wrong")
	if err != nil {
		t.Fatalf("ClientCredentialsTokenSource: %v", err)
	}
	if state, _ := ClassifySession(source.Token()); state != SessionRejected {
		t.Errorf("state = %s, want %s", state, SessionRejected)
	}
}

func TestClientCredentialsTokenSource_RefusesAnEmptySecret(t *testing.T) {
	idp := newServiceIDP(t, "prod-cli-scheduler", "s3cret", 3600)
	if _, err := ClientCredentialsTokenSource(context.Background(), serviceConfig(idp.server.URL, "prod.items.read"), ""); err == nil {
		t.Fatal("an empty secret was accepted")
	}
	if requests, _, _ := idp.seen(); requests != 0 {
		t.Errorf("token requests = %d, want 0", requests)
	}
}
