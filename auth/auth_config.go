package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type Config struct {
	Providers []ProviderConfig `yaml:"providers"`
}

type ProviderConfig struct {
	Type         ProviderType `yaml:"type"`
	Name         string       `yaml:"name"`
	ClientID     string       `yaml:"clientID"`
	ClientSecret string       `yaml:"clientSecret"`
	Endpoint     string       `yaml:"endpoint"`
}

type ProviderType string

type Provider struct {
	Name string
	Type ProviderType
	*oauth2.Config

	OIDCProvider *oidc.Provider
}

const (
	ProviderGitHub = "github"
	ProviderOIDC   = "oidc"
)

type OIDCClaims struct {
	jwt.RegisteredClaims
	Name  string `json:"name"`
	Email string `json:"email"`
}

func GenerateProviders(
	ctx context.Context,
	config Config,
	redirectURL string,
) (pp map[string]Provider, err error) {
	pp = make(map[string]Provider)
	for _, p := range config.Providers {
		switch p.Type {
		case ProviderGitHub:
			pp[strings.ToLower(p.Name)] = Provider{
				Name: p.Name,
				Type: p.Type,
				Config: &oauth2.Config{
					ClientID:     p.ClientID,
					ClientSecret: p.ClientSecret,
					Endpoint:     github.Endpoint,
					RedirectURL:  redirectURL,
					Scopes:       []string{"read:user", "user:email"},
				},
			}
		case ProviderOIDC:
			provider, err := oidc.NewProvider(ctx, p.Endpoint)
			if err != nil {
				return pp, err
			}
			pp[strings.ToLower(p.Name)] = Provider{
				Name: p.Name,
				Type: p.Type,
				Config: &oauth2.Config{
					ClientID:     p.ClientID,
					ClientSecret: p.ClientSecret,
					Endpoint:     provider.Endpoint(),
					RedirectURL:  redirectURL,
					Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
				},
				OIDCProvider: provider,
			}
		default:
			panic(fmt.Sprintf("unknown provider: %s", p.Type))
		}
	}
	return pp, nil
}