package goclilogin

import (
	"sync"

	"github.com/zalando/go-keyring"
)

// memoryKeyring is an in-memory stand-in for the OS keychain, behind
// NewTestTokenStore. It is guarded because the thing it stands in for is shared
// by every process on the machine, and the refresh path reads and writes it
// from several goroutines.
type memoryKeyring struct {
	mu      sync.Mutex
	entries map[string]string
}

func newMemoryKeyring() *memoryKeyring {
	return &memoryKeyring{entries: map[string]string{}}
}

func memoryKey(service, user string) string { return service + "\x00" + user }

func (m *memoryKeyring) Set(service, user, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[memoryKey(service, user)] = password
	return nil
}

func (m *memoryKeyring) Get(service, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[memoryKey(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (m *memoryKeyring) Delete(service, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := memoryKey(service, user)
	if _, ok := m.entries[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(m.entries, key)
	return nil
}
