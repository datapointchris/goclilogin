package goclilogin

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ServiceClient is a confidential client that a service authenticates as, with
// no person present. It is not a Config because nothing about the device grant
// applies to it: there is no keychain, no state directory and no default scope.
type ServiceClient struct {
	// Issuer is the OIDC provider's base URL. Discovery hangs off it.
	Issuer string

	// ClientID is the confidential client registered for the service. It is
	// never what the ClientID function returns. That names the public
	// device-grant client for one machine, which holds no secret and cannot use
	// this grant.
	ClientID string

	// Scopes are sent as given, and an empty list is refused. A provider that
	// grants only what a request names, Authelia among them, would otherwise
	// issue a token that can do nothing. openid and offline_access mean nothing
	// to this grant, and some providers refuse a client-credentials client that
	// holds them.
	Scopes []string
}

// ClientCredentialsTokenSource returns a token source for a confidential client
// that authenticates as itself with the client-credentials grant (RFC 6749
// §4.4). It is for a CLI run by a service, such as a scheduler, where no person
// is present to approve a device login.
//
// The secret is an argument because where it comes from is the caller's
// decision, as the client id already is. This package reads it from nowhere.
//
// Tokens live in memory for the life of the process, and a new one is
// requested when the last expires. Nothing is persisted and no lock is taken.
// The grant issues no refresh token, so there is nothing to store and no
// rotation for processes to race on.
//
// The client authenticates with HTTP Basic, the method RFC 6749 §2.3.1 requires
// every provider to support. ClassifySession reads a refusal the provider
// states as SessionRejected, and an unreachable provider as SessionUnverified.
func ClientCredentialsTokenSource(ctx context.Context, client ServiceClient, secret string) (oauth2.TokenSource, error) {
	if client.ClientID == "" {
		return nil, errors.New("client credentials need a client id")
	}
	if secret == "" {
		return nil, fmt.Errorf("client credentials for %s need a client secret", client.ClientID)
	}
	if len(client.Scopes) == 0 {
		return nil, fmt.Errorf("client credentials for %s need at least one scope", client.ClientID)
	}
	meta, err := discover(ctx, client.Issuer)
	if err != nil {
		return nil, err
	}
	if meta.TokenEndpoint == "" {
		return nil, errors.New("identity provider does not advertise a token_endpoint")
	}
	grant := &clientcredentials.Config{
		ClientID:     client.ClientID,
		ClientSecret: secret,
		TokenURL:     meta.TokenEndpoint,
		Scopes:       client.Scopes,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}
	return grant.TokenSource(ctx), nil
}
