// Package auth defines the authentication layer of the application.
package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Darkness4/auth-htmx/jwt"
	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
)

// Auth is a service that provides HTTP handlers and middlewares used for authentication.
type Auth struct {
	JWTSecret jwt.Secret
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

		userID, userName, err := provider.GetIdentity(r.Context(), oauth2Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := a.JWTSecret.GenerateToken(userID, userName, strings.ToLower(p))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// Logout removes session cookies and redirect to home.
func Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(jwt.TokenCookieKey)
	if err != nil {
		// Ignore error. Cookie doesn't exists.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	cookie.Value = ""
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(-1 * time.Hour)
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
