// Package memory implements a session store in-memory.
package memory

import (
	"context"

	"github.com/Darkness4/auth-htmx/auth/webauthn/session"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Store stores the login/registration session in-memory.
//
// In production, you should use a Redis or ETCD, or any distributed Key-Value database.
// Because of this, you cannot create replicas.
type Store struct {
	store map[string]*webauthn.SessionData
}

// NewStore instanciates a session store in memory.
func NewStore() *Store {
	return &Store{
		store: make(map[string]*webauthn.SessionData),
	}
}

// Get the login or registration session.
func (s *Store) Get(_ context.Context, userID []byte) (*webauthn.SessionData, error) {
	if v, ok := s.store[string(userID)]; ok {
		return v, nil
	}
	return nil, session.ErrNotFound
}

// Save the login or registration session.
func (s *Store) Save(_ context.Context, session *webauthn.SessionData) error {
	s.store[string(session.UserID)] = session
	return nil
}
