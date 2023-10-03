package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Darkness4/auth-htmx/jwt"
	"github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	userURL = "https://api.github.com/user"

	tokenCookieKey = "session_token"
)

type claimsContextKey struct{}

type Auth struct {
	JWT jwt.Service
	oauth2.Config
}

// Login is the handler that redirect to the authentication page of the OAuth Provider.
func (a *Auth) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := csrf.Token(r)
		cookie := &http.Cookie{
			Name:     "csrf_token",
			Value:    token,
			Expires:  time.Now().Add(1 * time.Minute), // Set expiration time as needed
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, a.Config.AuthCodeURL(token), http.StatusFound)
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

		accessToken, err := a.Config.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		user, err := getCurrentUser(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := a.JWT.GenerateToken(fmt.Sprintf("github:%d", user.ID), user.Login)
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

type user struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

func getCurrentUser(accessToken *oauth2.Token) (user, error) {
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return user{}, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken.AccessToken))
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
