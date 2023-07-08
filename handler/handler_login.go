package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Darkness4/auth-htmx/jwt"
	"github.com/Darkness4/auth-htmx/utils"
	"github.com/gorilla/csrf"
)

const (
	userURL = "https://api.github.com/user"
)

type AuthenticationService struct {
	JWT              jwt.Service
	AuthorizationURL string
	AccessTokenURL   string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
}

func (s *AuthenticationService) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := csrf.Token(r)
		params := url.Values{
			"client_id":    []string{s.ClientID},
			"redirect_uri": []string{s.RedirectURI},
			"scope":        []string{"read:user,user:email"},
			"state":        []string{token},
		}
		u := utils.Must(url.ParseRequestURI(s.AuthorizationURL))
		u.RawQuery = params.Encode()
		cookie := &http.Cookie{
			Name:     "csrf_token",
			Value:    token,
			Expires:  time.Now().Add(1 * time.Minute), // Set expiration time as needed
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

func (s *AuthenticationService) CallBack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		val, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		code := val.Get("code")
		state := val.Get("state")
		expectedState, err := r.Cookie("csrf_token")
		if err == http.ErrNoCookie {
			http.Error(w, "no csrf cookie error", http.StatusUnauthorized)
			return
		}
		if state != expectedState.Value {
			http.Error(w, "csrf error", http.StatusUnauthorized)
			return
		}

		accessToken, err := s.getAccessToken(s.ClientID, s.ClientSecret, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		user, err := getCurrentUser(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if err := s.JWT.GenerateTokenAndStore(w, fmt.Sprintf("github:%d", user.ID), user.Login); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func (s *AuthenticationService) getAccessToken(
	clientID string,
	clientSecret string,
	code string,
) (string, error) {
	params := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
		"code":          []string{code},
	}
	u := utils.Must(url.ParseRequestURI(s.AccessTokenURL))
	u.RawQuery = params.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var accessTokenResponse accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&accessTokenResponse); err != nil {
		return "", err
	}
	return accessTokenResponse.AccessToken, nil
}

type user struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

func getCurrentUser(accessToken string) (user, error) {
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return user{}, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return user{}, err
	}
	defer resp.Body.Close()

	var u user
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return user{}, err
	}
	return u, nil
}
