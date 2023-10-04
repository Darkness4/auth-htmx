package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCProvider struct {
	Name string
	*oauth2.Config

	*oidc.Provider
}

func (p *OIDCProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return p.Config.AuthCodeURL(state, opts...)
}

func (p *OIDCProvider) Exchange(
	ctx context.Context,
	code string,
	opts ...oauth2.AuthCodeOption,
) (*oauth2.Token, error) {
	return p.Config.Exchange(ctx, code, opts...)
}

func (p *OIDCProvider) DisplayName() string {
	return p.Name
}

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
