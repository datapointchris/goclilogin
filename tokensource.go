package goclilogin

import (
	"context"
	"errors"
	"fmt"
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

	// SessionRejected means the provider refused the refresh. Only an
	// interactive login fixes it.
	SessionRejected SessionState = "rejected"

	// SessionUnverified means the provider could not be reached to ask, which
	// proves nothing about the grant either way.
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

// ClassifySession reads the outcome of asking for a token. A refusal at the
// token endpoint is the provider saying the grant is gone; every other error is
// this machine failing to ask, which must not be reported as though it settled
// anything.
func ClassifySession(token *oauth2.Token, err error) (SessionState, *oauth2.Token) {
	if err == nil {
		return SessionLive, token
	}
	if IsSessionRejected(err) {
		return SessionRejected, nil
	}
	return SessionUnverified, nil
}

// IsSessionRejected reports whether err is the provider refusing a refresh,
// anywhere in its chain.
//
// It is worth a helper because of where the refusal surfaces. A refresh happens
// inside the transport of whichever request triggered it, so the failure
// reaches a command as that request's error — carrying a URL and a raw OAuth
// description, and naming nothing the user can do. Callers use this to print
// the one command that changes the situation.
func IsSessionRejected(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	return errors.As(err, &retrieveErr)
}
