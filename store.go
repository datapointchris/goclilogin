package goclilogin

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// ErrNotLoggedIn is returned when no token is stored for the client. It is a
// normal state rather than a fault, so callers branch on it and print a login
// hint instead of an error.
var ErrNotLoggedIn = errors.New("not logged in")

// storedToken is the on-disk shape. oauth2.Token keeps the id_token only in its
// Extra map, which does not survive a JSON round-trip, so it is persisted
// explicitly alongside the standard fields.
type storedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
	IDToken      string    `json:"id_token,omitempty"`
}

func (s storedToken) toOAuth2() *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		TokenType:    s.TokenType,
		Expiry:       s.Expiry,
	}
	if s.IDToken != "" {
		tok = tok.WithExtra(map[string]any{"id_token": s.IDToken})
	}
	return tok
}

func fromOAuth2(tok *oauth2.Token) storedToken {
	s := storedToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
	}
	if id, ok := tok.Extra("id_token").(string); ok {
		s.IDToken = id
	}
	return s
}

// keyringBackend is the seam that lets tests swap the OS keychain for an
// in-memory fake. go-keyring's own MockInit is process-global and racy under
// parallel tests, so the store depends on this interface instead.
type keyringBackend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

// TokenStore persists OAuth tokens in the OS keychain under one service name.
type TokenStore struct {
	service string
	backend keyringBackend
}

// NewTokenStore returns a store writing under service, which is the value a
// Config carries as KeyringService.
func NewTokenStore(service string) *TokenStore {
	return &TokenStore{service: service, backend: osKeyring{}}
}

// NewTestTokenStore returns a store backed by an in-memory map. It exists so a
// consumer can test its own command wiring without touching the real keychain,
// which is shared machine state that tests must not write.
func NewTestTokenStore(service string) *TokenStore {
	return &TokenStore{service: service, backend: newMemoryKeyring()}
}

// Save writes the token for clientID, replacing whatever was there. The id
// token rides along in a field of its own, because oauth2.Token keeps it in an
// Extra map that does not survive a JSON round-trip.
func (t *TokenStore) Save(clientID string, tok *oauth2.Token) error {
	data, err := json.Marshal(fromOAuth2(tok))
	if err != nil {
		return err
	}
	return t.backend.Set(t.service, clientID, string(data))
}

// Load returns the stored token for clientID, or ErrNotLoggedIn when the
// keychain holds nothing for it. A missing entry is a normal state rather than
// a fault, so callers branch on it and print a login hint.
func (t *TokenStore) Load(clientID string) (*oauth2.Token, error) {
	raw, err := t.backend.Get(t.service, clientID)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	var s storedToken
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, err
	}
	return s.toOAuth2(), nil
}

// Delete removes the stored token for clientID, returning ErrNotLoggedIn when
// there was nothing to remove. It does not revoke the grant at the provider —
// this machine simply forgets it.
func (t *TokenStore) Delete(clientID string) error {
	err := t.backend.Delete(t.service, clientID)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotLoggedIn
	}
	return err
}
