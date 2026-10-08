package goclilogin

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientCredentialsTokenSource returns a token source for a confidential client
// that authenticates as itself with the client-credentials grant (RFC 6749
// §4.4). It is for a CLI run by a service, such as a scheduler, where no person
// is present to approve a device login.
//
// The secret is an argument because where it comes from is the caller's
// decision, as the client id already is. This package reads it from nowhere.
//
// Only Issuer, ClientID and Scopes are read from cfg. Scopes is sent as given,
// and DefaultScopes does not apply: openid and offline_access mean nothing to
// this grant, and some providers, Authelia among them, refuse a
// client-credentials client that holds them. A provider that grants only what a
// request names needs the scopes set here.
//
// Tokens live in memory for the life of the process, and a new one is
// requested when the last expires. Nothing is persisted and no lock is taken.
// The grant issues no refresh token, so there is nothing to store and no
// rotation for processes to race on.
//
// The client authenticates with HTTP Basic, the method RFC 6749 §2.3.1 requires
// every provider to support. A refused request surfaces as an
// *oauth2.RetrieveError, which ClassifySession reads as SessionRejected.
func ClientCredentialsTokenSource(ctx context.Context, cfg Config, secret string) (oauth2.TokenSource, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("client credentials need a client id")
	}
	if secret == "" {
		return nil, fmt.Errorf("client credentials for %s need a client secret", cfg.ClientID)
	}
	meta, err := discover(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if meta.TokenEndpoint == "" {
		return nil, errors.New("identity provider does not advertise a token_endpoint")
	}
	grant := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: secret,
		TokenURL:     meta.TokenEndpoint,
		Scopes:       cfg.Scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}
	return grant.TokenSource(ctx), nil
}
