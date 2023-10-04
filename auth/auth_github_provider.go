package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type GitHubProvider struct {
	Name string
	*oauth2.Config
}

func (p *GitHubProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return p.Config.AuthCodeURL(state, opts...)
}

func (p *GitHubProvider) Exchange(
	ctx context.Context,
	code string,
	opts ...oauth2.AuthCodeOption,
) (*oauth2.Token, error) {
	return p.Config.Exchange(ctx, code, opts...)
}

func (p *GitHubProvider) DisplayName() string {
	return p.Name
}

func (p *GitHubProvider) GetIdentity(
	ctx context.Context,
	token *oauth2.Token,
) (userID string, userName string, err error) {
	user, err := getGithubUser(ctx, token.AccessToken)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%s:%d", strings.ToLower(p.Name), user.ID), user.Login, err
}

type githubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

func getGithubUser(ctx context.Context, accessToken string) (githubUser, error) {
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return githubUser{}, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Accept", "application/vnd.github+json")
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return githubUser{}, err
	}
	defer resp.Body.Close()

	var u githubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return githubUser{}, err
	}
	return u, nil
}
