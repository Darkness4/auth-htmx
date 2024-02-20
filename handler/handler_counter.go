// Package handler containers HTTP handling functions.
package handler

import (
	"fmt"
	"net/http"

	"github.com/Darkness4/auth-htmx/database/counter"
	"github.com/Darkness4/auth-htmx/jwt"
)

// Count increments the counter and returns the new value.
func Count(counter *counter.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "not allowed", http.StatusUnauthorized)
			return
		}
		newValue, err := counter.Inc(r.Context(), claims.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%d", newValue)
	}
}
