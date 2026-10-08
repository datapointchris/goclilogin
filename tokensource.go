package goclilogin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// lockingTokenSource refreshes at most one token at a time per machine and
// writes the result back to the keychain, so a refresh performed by one process
// is the one every other process goes on to use.
//
// The reason this is not a plain oauth2.ReuseTokenSource is in the package
// documentation: a provider that rotates refresh tokens revokes the whole grant
// when a consumed one is replayed, so an unserialized refresh across processes
// costs an interactive login.
type lockingTokenSource struct {
	ctx      context.Context
	oauthCfg *oauth2.Config
	store    *TokenStore
	clientID string
	lockDir  string

	// mu serializes the goroutines inside one process; the file lock serializes
	// the processes. Both carry real traffic — a command that fetches several
	// resources concurrently shares one token source across its goroutines.
	mu  sync.Mutex
	tok *oauth2.Token
}

func (l *lockingTokenSource) Token() (*oauth2.Token, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.tok.Valid() {
		return l.tok, nil
	}

	release := lockRefresh(l.lockDir, l.clientID)
	defer release()

	// Whoever held the lock may have refreshed while this process waited for
	// it. Their token is then the live one, and refreshing again would present
	// the token their rotation already consumed.
	if stored, _, err := l.store.Load(l.clientID); err == nil {
		l.tok = stored
		if stored.Valid() {
			return stored, nil
		}
	}

	refreshed, err := l.oauthCfg.TokenSource(l.ctx, l.tok).Token()
	if err != nil {
		return nil, err
	}
	l.tok = refreshed
	if _, err := l.store.Save(l.clientID, refreshed); err != nil {
		return refreshed, fmt.Errorf("persist refreshed token: %w", err)
	}
	return refreshed, nil
}

// TokenSource returns an auto-refreshing, keychain-persisting token source for
// the logged-in client, or ErrNotLoggedIn if there is no stored token.
//
// Wrap it with oauth2.NewClient to get an *http.Client that injects and renews
// the bearer token on every request, so resource code never handles tokens.
func TokenSource(ctx context.Context, cfg Config, store *TokenStore) (oauth2.TokenSource, error) {
	tok, _, err := store.Load(cfg.ClientID)
	if err != nil {
		return nil, err
	}
	meta, err := discover(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return &lockingTokenSource{
		ctx:      ctx,
		oauthCfg: oauthConfig(cfg, meta),
		store:    store,
		clientID: cfg.ClientID,
		lockDir:  cfg.stateDir(),
		tok:      tok,
	}, nil
}

// SessionState is what asking the provider for a usable token established.
type SessionState string

const (
	// SessionLive means a usable access token was obtained.
	SessionLive SessionState = "live"

	// SessionRejected means the provider stated that it refuses to issue a
	// token. For a device-grant session that is a refused refresh, which only
	// an interactive login fixes. For a client-credentials client it is the
	// client's own request refused. The secret or the client's registration is
	// what needs fixing there.
	SessionRejected SessionState = "rejected"

	// SessionUnverified means no refusal was stated. The provider could not be
	// reached, a proxy in front of it answered instead, or it answered with a
	// 5xx or a 429. That proves nothing about the grant either way.
	SessionUnverified SessionState = "unverified"
)

// VerifySession obtains a token the way a resource call does and reports which
// state the session is in, along with whatever token it ended up holding.
//
// This is the only thing that separates a soft expiry from a revoked grant. A
// stored token says what the machine holds, not what the provider will honor,
// and a status command that reads only the local expiry will call a dead grant
// healthy. A live access token answers without a network call; an expired one
// performs the refresh the next call would have performed anyway.
func VerifySession(ctx context.Context, cfg Config, store *TokenStore) (SessionState, *oauth2.Token) {
	source, err := TokenSource(ctx, cfg, store)
	if err != nil {
		return SessionUnverified, nil
	}
	return ClassifySession(source.Token())
}

// ClassifySession reads the outcome of asking for a token. A refusal the
// provider states is SessionRejected. Every other error is SessionUnverified,
// because no answer about the grant came back.
func ClassifySession(token *oauth2.Token, err error) (SessionState, *oauth2.Token) {
	if err == nil {
		return SessionLive, token
	}
	if IsSessionRejected(err) {
		return SessionRejected, nil
	}
	return SessionUnverified, nil
}

// IsSessionRejected reports whether err, anywhere in its chain, is the provider
// stating that it refuses to issue a token. x/oauth2 returns a RetrieveError
// for every non-2xx answer, so the type alone proves nothing. A refusal is an
// OAuth error code on any answer but a 5xx or a 429. Those two say the server
// failed or is shedding load, so a code they carry is about the moment rather
// than the grant. A proxy's 502 page carries no code at all.
//
// RFC 6749 §5.2 puts a refusal on a 400 or 401. x/oauth2 also accepts one on a
// 200, which some providers send. So the status is checked for failure rather
// than matched against those two.
//
// A refresh happens inside the transport of whichever request triggered it, so
// a refusal reaches a command as that request's error. That error carries a URL
// and a raw OAuth description, and names nothing the user can do. Callers use
// this to tell the user what fixes it: a new login for a device-grant session,
// or the secret or the client's registration for a client-credentials one.
func IsSessionRejected(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) || retrieveErr.ErrorCode == "" || retrieveErr.Response == nil {
		return false
	}
	status := retrieveErr.Response.StatusCode
	return status < http.StatusInternalServerError && status != http.StatusTooManyRequests
}
