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
