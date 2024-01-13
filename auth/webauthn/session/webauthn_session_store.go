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

var ErrNotFound = errors.New("not found in session store")

// StoreInMemory stores the login/registration session in-memory.
//
// In production, you should use a Redis or ETCD, or any distributed Key-Value database.
// Because of this, you cannot create replicas.
type StoreInMemory struct {
	store map[string]*webauthn.SessionData
}

func NewInMemory() Store {
	return &StoreInMemory{
		store: make(map[string]*webauthn.SessionData),
	}
}

func (s *StoreInMemory) Get(ctx context.Context, userID []byte) (*webauthn.SessionData, error) {
	if v, ok := s.store[string(userID)]; ok {
		return v, nil
	}
	return nil, ErrNotFound
}

func (s *StoreInMemory) Save(ctx context.Context, session *webauthn.SessionData) error {
	s.store[string(session.UserID)] = session
	return nil
}
