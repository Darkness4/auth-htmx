package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Darkness4/auth-htmx/jwt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
)

const (
	userURL = "https://api.github.com/user"

	tokenCookieKey = "session_token"
)

type claimsContextKey struct{}

type Auth struct {
	JWT       jwt.Service
	Providers map[string]Provider
}

// Login is the handler that redirect to the authentication page of the OAuth Provider.
func (a *Auth) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		val, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		p := val.Get("provider")

		provider, ok := a.Providers[strings.ToLower(p)]
		if !ok {
			http.Error(w, "auth provider not known", http.StatusUnauthorized)
			return
		}

		token := csrf.Token(r)
		cookie := &http.Cookie{
			Name:     "csrf_token",
			Value:    token,
			Expires:  time.Now().Add(1 * time.Minute), // Set expiration time as needed
			HttpOnly: true,
		}
		// State contain the provider and the csrf token.
		state := fmt.Sprintf("%s,%s", token, p)
		http.SetCookie(w, cookie)
		http.Redirect(
			w,
			r,
			provider.AuthCodeURL(state),
			http.StatusFound,
		)
	}
}

// CallBack is the handler called after login.
//
// It:
//
// 1. Fetches the accessToken
// 2. Fetches some user info and wrap them in a JWT token
// 3. Store the JWT token in a cookie for the browser.
func (a *Auth) CallBack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		val, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		code := val.Get("code")
		csrfToken, p, ok := strings.Cut(val.Get("state"), ",")
		if !ok {
			log.Error().Msg(fmt.Sprintf("invalid state: %s", val.Get("state")))
			http.Error(
				w,
				fmt.Sprintf("invalid state: %s", val.Get("state")),
				http.StatusInternalServerError,
			)
			return
		}

		expectedCSRF, err := r.Cookie("csrf_token")
		if err == http.ErrNoCookie {
			http.Error(w, "no csrf cookie error", http.StatusUnauthorized)
			return
		}
		if csrfToken != expectedCSRF.Value {
			http.Error(w, "csrf error", http.StatusUnauthorized)
			return
		}

		provider, ok := a.Providers[strings.ToLower(p)]
		if !ok {
			http.Error(w, "auth provider not known", http.StatusUnauthorized)
			return
		}

		oauth2Token, err := provider.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var userID, userName string
		switch provider.Type {
		case ProviderGitHub:
			user, err := getGithubUser(oauth2Token.AccessToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			userID = fmt.Sprintf("%s:%d", p, user.ID)
			userName = user.Login
		case ProviderOIDC:
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				log.Error().Any("provider", provider).Msg("missing ID token")
				http.Error(w, "missing ID token", http.StatusInternalServerError)
				return
			}
			idToken, err := provider.OIDCProvider.Verifier(&oidc.Config{
				ClientID: provider.ClientID,
			}).Verify(r.Context(), rawIDToken)
			if err != nil {
				log.Error().Err(err).Msg("failed to verify ID token")
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			claims := OIDCClaims{}
			if err := idToken.Claims(&claims); err != nil {
				log.Error().Err(err).Msg("failed to parse ID token")
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			userID = fmt.Sprintf("%s:%s", p, claims.Subject)
			userName = claims.Name
		}

		token, err := a.JWT.GenerateToken(userID, userName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     tokenCookieKey,
			Value:    token,
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (a *Auth) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(tokenCookieKey)
		if err != nil {
			// Ignore error. Cookie doesn't exists.
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		cookie.Expires = time.Now().Add(-1 * time.Hour)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT token from the request header
		cookie, err := r.Cookie(tokenCookieKey)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Verify the JWT token
		claims, err := a.JWT.VerifyToken(cookie.Value)
		if err != nil {
			log.Error().Err(err).Msg("token verification failed")
			next.ServeHTTP(w, r)
			return
		}

		// Store the claims in the request context for further use
		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaimsFromRequest(r *http.Request) (claims *jwt.Claims, ok bool) {
	claims, ok = r.Context().Value(claimsContextKey{}).(*jwt.Claims)
	return claims, ok
}

type githubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

func getGithubUser(accessToken string) (githubUser, error) {
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return githubUser{}, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("Accept", "application/vnd.github+json")
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
