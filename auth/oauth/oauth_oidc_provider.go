package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider is a authentication provider which uses OpenID Connect.
type OIDCProvider struct {
	Name string
	*oauth2.Config

	*oidc.Provider
}

// DisplayName returns the public name of the authenticated user.
func (p *OIDCProvider) DisplayName() string {
	return p.Name
}

// GetIdentity fetches the identity of the authenticated user from the ID token.
//
// It returns <provider>:<user id>.
func (p *OIDCProvider) GetIdentity(
	ctx context.Context,
	token *oauth2.Token,
) (userID string, userName string, err error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", "", errors.New("missing ID token")
	}
	idToken, err := p.Provider.Verifier(&oidc.Config{
		ClientID: p.ClientID,
	}).Verify(ctx, rawIDToken)
	if err != nil {
		return "", "", err
	}
	claims := OIDCClaims{}
	if err := idToken.Claims(&claims); err != nil {
		return "", "", err
	}

	return fmt.Sprintf("%s:%s", strings.ToLower(p.Name), claims.Subject), claims.Name, nil
}
