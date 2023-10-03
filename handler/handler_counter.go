package handler

import (
	"fmt"
	"net/http"

	"github.com/Darkness4/auth-htmx/auth"
	"github.com/Darkness4/auth-htmx/database/counter"
)

func Count(counter counter.Repository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "not allowed", http.StatusUnauthorized)
			return
		}
		new, err := counter.Inc(r.Context(), claims.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%d", new)
	}
}
