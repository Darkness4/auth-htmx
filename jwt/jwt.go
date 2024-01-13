// Package jwt defines all the methods for JWT manipulation.
package jwt

import (
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
)

// ExpiresDuration is the duration when a user session expires.
const ExpiresDuration = 24 * time.Hour

// Claims are the fields stored in a JWT.
type Claims struct {
	jwt.RegisteredClaims
	Provider    string                `json:"provider"`
	Credentials []webauthn.Credential `json:"credentials"`
}

// Secret is a HMAC JWT secret used for signing.
type Secret []byte

// Option is an option for JWT.
type Option func(*Options)

// Options is the struct storing the options for JWT.
type Options struct {
	credentials []webauthn.Credential
}

func applyOptions(opts []Option) *Options {
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// WithCredentials exports Webauthn credentials in the JWT.
func WithCredentials(credentials []webauthn.Credential) Option {
	return func(o *Options) {
		o.credentials = credentials
	}
}

// GenerateToken creates a JWT session token which stores the user identity.
//
// The returned token is signed with the JWT secret, meaning it cannot be falsified.
func (s Secret) GenerateToken(
	userID string,
	userName string,
	provider string,
	options ...Option,
) (string, error) {
	o := applyOptions(options)
	// Create the token claims
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        userID,
			Subject:   userName,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ExpiresDuration)),
		},
		Provider:    provider,
		Credentials: o.credentials,
	}

	// Create the token object
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(s))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// VerifyToken checks if the token signature is valid compared to the JWT secret.
func (s Secret) VerifyToken(tokenString string) (*Claims, error) {
	// Parse the token
	var claims Claims
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			// Make sure the signing method is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}

			// Return the secret key for validation
			return []byte(s), nil
		},
	)
	if err != nil {
		return nil, err
	}

	// Verify and return the claims
	if token.Valid {
		return &claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
