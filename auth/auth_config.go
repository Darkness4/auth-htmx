package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/Darkness4/auth-htmx/auth/oauth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Config is the authentication configuration definition for the application.
type Config struct {
	Providers     []oauth.ProviderConfig `yaml:"providers"`
	SelfHostUsers bool                   `yaml:"selfHostUsers"`
}

// GenerateProviders generates a map of provider based on the given configuration.
func GenerateProviders(
	ctx context.Context,
	config Config,
	redirectURL string,
) (pp map[string]oauth.Provider, err error) {
	pp = make(map[string]oauth.Provider)
	for _, p := range config.Providers {
		switch p.Type {
		case oauth.ProviderGitHub:
			pp[strings.ToLower(p.Name)] = &oauth.GitHubProvider{
				Name: p.Name,
				Config: &oauth2.Config{
					ClientID:     p.ClientID,
					ClientSecret: p.ClientSecret,
					Endpoint:     github.Endpoint,
					RedirectURL:  redirectURL,
					Scopes:       []string{"read:user", "user:email"},
				},
			}
		case oauth.ProviderOIDC:
			provider, err := oidc.NewProvider(ctx, p.Endpoint)
			if err != nil {
				return pp, err
			}
			pp[strings.ToLower(p.Name)] = &oauth.OIDCProvider{
				Name: p.Name,
				Config: &oauth2.Config{
					ClientID:     p.ClientID,
					ClientSecret: p.ClientSecret,
					Endpoint:     provider.Endpoint(),
					RedirectURL:  redirectURL,
					Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
				},
				Provider: provider,
			}
		default:
			panic(fmt.Sprintf("unknown provider: %s", p.Type))
		}
	}
	return pp, nil
}
