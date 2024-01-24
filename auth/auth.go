// Package auth defines the authentication layer of the application.
package auth

import (
	"net/http"
	"time"

	"github.com/Darkness4/auth-htmx/jwt"
)

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
