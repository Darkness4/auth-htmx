package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Darkness4/auth-htmx/database"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Repository defines the user methods.
type Repository interface {
	GetOrCreateByName(ctx context.Context, name string) (*User, error)
	GetByName(ctx context.Context, name string) (*User, error)
	Create(ctx context.Context, name string, displayName string) (*User, error)
	AddCredential(ctx context.Context, id []byte, credential *webauthn.Credential) error
	UpdateCredential(ctx context.Context, credential *webauthn.Credential) error
}

// NewRepository wraps around a SQL database to execute the counter methods.
func NewRepository(db *sql.DB) Repository {
	return &repository{
		Queries: database.New(db),
	}
}

type repository struct {
	*database.Queries
}

// AddCredential to a user from the database.
func (r *repository) AddCredential(
	ctx context.Context,
	id []byte,
	credential *webauthn.Credential,
) error {
	transport, err := json.Marshal(credential.Transport)
	if err != nil {
		return err
	}
	flags, err := json.Marshal(credential.Flags)
	if err != nil {
		return err
	}
	authenticator, err := json.Marshal(credential.Authenticator)
	if err != nil {
		return err
	}

	return r.Queries.CreateCredential(ctx, database.CreateCredentialParams{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       transport,
		Flags:           flags,
		Authenticator:   authenticator,
		UserID:          id,
	})
}

// UpdateCredential of a user from the database.
func (r *repository) UpdateCredential(ctx context.Context, credential *webauthn.Credential) error {
	transport, err := json.Marshal(credential.Transport)
	if err != nil {
		return err
	}
	flags, err := json.Marshal(credential.Flags)
	if err != nil {
		return err
	}
	authenticator, err := json.Marshal(credential.Authenticator)
	if err != nil {
		return err
	}

	return r.Queries.UpdateCredential(ctx, database.UpdateCredentialParams{
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       transport,
		Flags:           flags,
		Authenticator:   authenticator,

		ByID: credential.ID,
	})
}

// Create a user in the database.
//
// The user ID is completely randomized.
func (r *repository) Create(ctx context.Context, name string, displayName string) (*User, error) {
	id := make([]byte, 64)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	u, err := r.Queries.CreateUser(ctx, database.CreateUserParams{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, err
	}

	return fromModel(&u, []webauthn.Credential{}), nil
}

// GetOrCreateByName a user from the databse.
func (r *repository) GetOrCreateByName(ctx context.Context, name string) (*User, error) {
	u, err := r.GetByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		u, err = r.Create(ctx, name, name)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return u, nil
}

// GetByName a user from the database.
func (r *repository) GetByName(ctx context.Context, name string) (*User, error) {
	u, err := r.Queries.GetUserByName(ctx, name)
	if err != nil {
		return nil, err
	}

	credentials, err := r.getCredentialsByUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}

	return fromModel(&u, credentials), nil
}

func (r *repository) getCredentialsByUser(
	ctx context.Context,
	id []byte,
) ([]webauthn.Credential, error) {
	cc, err := r.Queries.GetCredentialsByUser(ctx, id)
	if err != nil {
		return nil, err
	}

	credentials := make([]webauthn.Credential, 0, len(cc))
	for _, c := range cc {
		credentials = append(credentials, credentialFromModel(&c))
	}
	return credentials, nil
}
