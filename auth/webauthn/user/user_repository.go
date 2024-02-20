// Package user describes the methods to handle users needed for webauthn.
package user

import (
	"context"

	"github.com/Darkness4/auth-htmx/database/user"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Repository defines the user methods needed for webauthn.
type Repository interface {
	GetOrCreateByName(ctx context.Context, name string) (*user.User, error)
	GetByName(ctx context.Context, name string) (*user.User, error)
	Get(ctx context.Context, id []byte) (*user.User, error)
	Create(ctx context.Context, name string, displayName string) (*user.User, error)
	AddCredential(ctx context.Context, id []byte, credential *webauthn.Credential) error
	UpdateCredential(ctx context.Context, credential *webauthn.Credential) error
	RemoveCredential(ctx context.Context, id []byte, credentialID []byte) error
}
