package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Darkness4/auth-htmx/database"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// NewRepository instanciates a new user repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		Queries: database.New(db),
	}
}

// Repository wraps around a SQL database to execute the webauthn methods.
type Repository struct {
	*database.Queries
}

var (
	// ErrUserNotFound happens when the user if not found in the database.
	ErrUserNotFound = errors.New("user not found")
	// ErrCredentialNotFound happens when the credential if not found in the database.
	ErrCredentialNotFound = errors.New("credential not found")
)

// AddCredential to a user from the database.
func (r *Repository) AddCredential(
	ctx context.Context,
	id []byte,
	credential *webauthn.Credential,
) error {
	if credential.Transport == nil {
		credential.Transport = []protocol.AuthenticatorTransport{}
	}
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

	return r.CreateCredential(ctx, database.CreateCredentialParams{
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
func (r *Repository) UpdateCredential(ctx context.Context, credential *webauthn.Credential) error {
	if credential.Transport == nil {
		credential.Transport = []protocol.AuthenticatorTransport{}
	}
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
func (r *Repository) Create(ctx context.Context, name string, displayName string) (*User, error) {
	id := make([]byte, 64)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	u, err := r.CreateUser(ctx, database.CreateUserParams{
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
func (r *Repository) GetOrCreateByName(ctx context.Context, name string) (*User, error) {
	u, err := r.GetByName(ctx, name)
	if errors.Is(err, ErrUserNotFound) {
		u, err = r.Create(ctx, name, name)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return u, nil
}

// Get a user from the database.
func (r *Repository) Get(ctx context.Context, id []byte) (*User, error) {
	u, err := r.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	credentials, err := r.getCredentialsByUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}

	return fromModel(&u, credentials), nil
}

// GetByName a user from the database.
func (r *Repository) GetByName(ctx context.Context, name string) (*User, error) {
	u, err := r.GetUserByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	credentials, err := r.getCredentialsByUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}

	return fromModel(&u, credentials), nil
}

func (r *Repository) getCredentialsByUser(
	ctx context.Context,
	id []byte,
) ([]webauthn.Credential, error) {
	cc, err := r.GetCredentialsByUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCredentialNotFound
	} else if err != nil {
		return nil, err
	}

	credentials := make([]webauthn.Credential, 0, len(cc))
	for _, c := range cc {
		credentials = append(credentials, credentialFromModel(&c))
	}
	return credentials, nil
}

// RemoveCredential of a user from the database.
func (r *Repository) RemoveCredential(
	ctx context.Context,
	id []byte,
	credentialID []byte,
) error {
	return r.DeleteCredential(ctx, database.DeleteCredentialParams{
		ID:     credentialID,
		UserID: id,
	})
}
