package goclilogin

import (
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

	// VerificationURI is the page to open, without the code embedded. This is
	// the one to show a human, because it is short enough to read off a screen
	// and type on another device.
	VerificationURI string

	// VerificationURIComplete carries the code already embedded, so a browser
	// that opens lands on an approval screen with nothing to type. Providers
	// are not required to send it, so it can be empty.
	VerificationURIComplete string
}

// BrowserURL is the URL to hand a browser: the complete one where the provider
// supplied it, the bare one otherwise.
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

	token, err := oauthCfg.DeviceAccessToken(ctx, deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("waiting for approval: %w", err)
	}
	return token, nil
}

// WriteInstructions is the conventional rendering of a DevicePrompt, offered so
// every CLI does not spell it out again. Write it to stderr, so a command that
// prints a token to stdout stays pipeable.
func WriteInstructions(w io.Writer, clientID string, p DevicePrompt) {
	_, _ = fmt.Fprintf(w, "\nSigning in as %s\n\n", clientID)
	_, _ = fmt.Fprintf(w, "  Code:  %s\n", p.UserCode)
	_, _ = fmt.Fprintf(w, "  Open:  %s\n\n", p.VerificationURI)
	_, _ = fmt.Fprintln(w, "Open that URL in any browser, on any device, and enter the code.")
	_, _ = fmt.Fprintln(w, "Waiting for approval...")
}
