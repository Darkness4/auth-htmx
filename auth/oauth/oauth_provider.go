package oauth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// ProviderConfig is the configuration of one provider to achieve the OAuth2 flow.
type ProviderConfig struct {
	Type         ProviderType `yaml:"type"`
	Name         string       `yaml:"name"`
	ClientID     string       `yaml:"clientID"`
	ClientSecret string       `yaml:"clientSecret"`
	Endpoint     string       `yaml:"endpoint"`
}

// ProviderType is a string uses the indentify edge cases in authentication.
type ProviderType string

const (
	// ProviderGitHub is the type of the authentication provider that uses GitHub OAuth2.
	ProviderGitHub ProviderType = "github"
	// ProviderOIDC is the generic type of authentication provider that uses OIDC.
	ProviderOIDC ProviderType = "oidc"
)

// Provider is the interface that defines the necessary methods of authentication providers.
type Provider interface {
	// AuthCodeURL returns the URL of the consent page that asks for permissions.
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	// Exchange converts a code into an OAuth2 token.
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)

	// DisplayName is the provider's name that can be displayed publicly.
	DisplayName() string
	GetIdentity(
		ctx context.Context,
		token *oauth2.Token,
	) (userID string, userName string, err error)
}

// OIDCClaims are the standard fields given by an OIDC provider.
type OIDCClaims struct {
	jwt.RegisteredClaims
	Name  string `json:"name"`
	Email string `json:"email"`
}
