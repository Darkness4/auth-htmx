// Package session handles the login/register sessions of webauthn.
package session

import (
	"context"
	"errors"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Store stores the login/registration session.
type Store interface {
	Save(ctx context.Context, session *webauthn.SessionData) error
	Get(ctx context.Context, userID []byte) (*webauthn.SessionData, error)
}

// ErrNotFound happens when the session is not found in the store.
var ErrNotFound = errors.New("not found in session store")

// StoreInMemory stores the login/registration session in-memory.
//
// In production, you should use a Redis or ETCD, or any distributed Key-Value database.
// Because of this, you cannot create replicas.
type StoreInMemory struct {
	store map[string]*webauthn.SessionData
}

// NewInMemory instanciates a session store in memory.
func NewInMemory() Store {
	return &StoreInMemory{
		store: make(map[string]*webauthn.SessionData),
	}
}

// Get the login or registration session.
func (s *StoreInMemory) Get(_ context.Context, userID []byte) (*webauthn.SessionData, error) {
	if v, ok := s.store[string(userID)]; ok {
		return v, nil
	}
	return nil, ErrNotFound
}

// Save the login or registration session.
func (s *StoreInMemory) Save(_ context.Context, session *webauthn.SessionData) error {
	s.store[string(session.UserID)] = session
	return nil
}
