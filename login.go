package goclilogin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// providerMetadata is the subset of the OIDC discovery document this package
// needs. A full OIDC client would read far more; a device-grant CLI needs the
// issuer it is talking to and the two endpoints it posts to.
type providerMetadata struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// discover fetches the OIDC discovery document for the issuer.
func discover(ctx context.Context, issuer string) (providerMetadata, error) {
	discoURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoURL, nil)
	if err != nil {
		return providerMetadata{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return providerMetadata{}, fmt.Errorf("reach identity provider at %s: %w", discoURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return providerMetadata{}, fmt.Errorf("identity provider discovery returned %s", resp.Status)
	}
	var meta providerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return providerMetadata{}, err
	}
	return meta, nil
}

// oauthConfig builds the oauth2 config used for the device grant and refresh.
// AuthStyle is pinned to InParams because a CLI is a public client with no
// secret: the client_id goes in the request body, and there is nothing to put
// in a Basic header.
func oauthConfig(cfg Config, meta providerMetadata) *oauth2.Config {
	return &oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			TokenURL:      meta.TokenEndpoint,
			DeviceAuthURL: meta.DeviceAuthorizationEndpoint,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
		Scopes: cfg.scopes(),
	}
}

// DevicePrompt is what the user has to act on: a code to type and a URL to open.
type DevicePrompt struct {
	// UserCode is what the user enters on the verification page.
	UserCode string

	// VerificationURI is the page to open, without the code embedded. Send a
	// user here only where VerificationURIComplete is empty: some providers,
	// Authelia among them, take a browser that is already signed in straight
	// past this page, and it then has nowhere to type the code.
	VerificationURI string

	// VerificationURIComplete carries the code already embedded, so a browser
	// that opens lands on an approval screen with nothing to type. Providers
	// are not required to send it, so it can be empty.
	VerificationURIComplete string
}

// BrowserURL is the URL to send a user to, whether a browser is opened on it
// or it is printed for one on another device: the complete one where the
// provider supplied it, the bare one otherwise.
func (p DevicePrompt) BrowserURL() string {
	if p.VerificationURIComplete != "" {
		return p.VerificationURIComplete
	}
	return p.VerificationURI
}

// Login runs the OAuth 2.0 device authorization grant (RFC 8628). It asks the
// provider for a device code, hands the prompt to the caller, and polls until
// the request is approved or the code expires.
//
// The caller owns presentation. show is called once with the code and URL, and
// must not return an error for a browser it could not open — that is the normal
// case over SSH, and the code is still displayed. Pass a ctx with a deadline;
// the device code carries its own expiry but a caller should bound the wait.
func Login(ctx context.Context, cfg Config, show func(DevicePrompt)) (*oauth2.Token, error) {
	meta, err := discover(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if meta.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("identity provider does not advertise a device_authorization_endpoint")
	}

	oauthCfg := oauthConfig(cfg, meta)
	deviceAuth, err := oauthCfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("request a device code: %w", err)
	}

	if show != nil {
		show(DevicePrompt{
			UserCode:                deviceAuth.UserCode,
			VerificationURI:         deviceAuth.VerificationURI,
			VerificationURIComplete: deviceAuth.VerificationURIComplete,
		})
	}

	token, err := pollForApproval(ctx, oauthCfg, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("waiting for approval: %w", err)
	}
	return token, nil
}

// pollForApproval polls the token endpoint until the device code is approved,
// refused or expired. The polling is x/oauth2's. That loop keeps going only on
// authorization_pending and slow_down, and returns on any other answer. So the
// HTTP client it polls through turns an answer asking it to wait into slow_down.
func pollForApproval(ctx context.Context, cfg *oauth2.Config, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	base, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	client.Transport = backOffAsSlowDown{next: next}
	return cfg.DeviceAccessToken(context.WithValue(ctx, oauth2.HTTPClient, &client), da)
}

// backOffAsSlowDown rewrites a token-endpoint answer that asks the client to
// wait into RFC 8628's slow_down. Two answers ask that besides slow_down: an
// HTTP 429 from whatever rate-limits the endpoint, and the OAuth error
// temporarily_unavailable, which Authelia sends when it rate-limits the endpoint
// itself. Either one would otherwise end a login still waiting for approval.
// Rewritten, each adds five seconds to the poll interval for this and every
// later poll (RFC 8628 § 3.5), and the poll continues until the device code
// expires.
type backOffAsSlowDown struct {
	next http.RoundTripper
}

func (t backOffAsSlowDown) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp.StatusCode < 300 {
		return resp, err
	}
	asksToWait := resp.StatusCode == http.StatusTooManyRequests
	if !asksToWait {
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		var answer struct {
			Error string `json:"error"`
		}
		asksToWait = json.Unmarshal(data, &answer) == nil && answer.Error == "temporarily_unavailable"
	}
	if !asksToWait {
		return resp, nil
	}
	_ = resp.Body.Close()
	const slowDown = `{"error":"slow_down"}`
	return &http.Response{
		Status:        "400 Bad Request",
		StatusCode:    http.StatusBadRequest,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(slowDown)),
		ContentLength: int64(len(slowDown)),
		Request:       req,
	}, nil
}

// WriteInstructions is the conventional rendering of a DevicePrompt, offered so
// every CLI does not spell it out again. Write it to stderr, so a command that
// prints a token to stdout stays pipeable.
//
// The URL printed is BrowserURL, the same one a local browser is handed, so
// a login approved on another device reaches the same approval screen. The
// code is printed as well: with the complete URL it is there to check against
// that screen, and with the bare one it is what the user types.
func WriteInstructions(w io.Writer, clientID string, p DevicePrompt) {
	_, _ = fmt.Fprintf(w, "\nSigning in as %s\n\n", clientID)
	_, _ = fmt.Fprintf(w, "  Code:  %s\n", p.UserCode)
	_, _ = fmt.Fprintf(w, "  Open:  %s\n\n", p.BrowserURL())
	if p.VerificationURIComplete != "" {
		_, _ = fmt.Fprintln(w, "Open that URL in any browser, on any device, and check it shows the code.")
	} else {
		_, _ = fmt.Fprintln(w, "Open that URL in any browser, on any device, and enter the code.")
	}
	_, _ = fmt.Fprintln(w, "Waiting for approval...")
}
