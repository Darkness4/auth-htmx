package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"

	"embed"

	"github.com/Darkness4/auth-htmx/handler"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

const debug = false

//go:embed pages/* base.html
var html embed.FS

func main() {
	log.Level(zerolog.DebugLevel)
	r := chi.NewRouter()
	r.Use(hlog.NewHandler(log.Logger))
	if debug {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log := hlog.FromRequest(r)
				log.Info().
					Timestamp().
					Fields(map[string]interface{}{
						"remote_ip": r.RemoteAddr,
						"url":       r.URL.Path,
						"proto":     r.Proto,
						"method":    r.Method,
					}).
					Msg("incoming_request")
				body, _ := httputil.DumpRequest(r, true)
				fmt.Println(string(body))

				next.ServeHTTP(w, r)
			})
		})
	}
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		t := template.Must(template.ParseFS(html, "base.html", "pages/page.tmpl"))
		t.ExecuteTemplate(w, "base", nil)
	})
	r.Post("/count", handler.Count)
	log.Info().Msg("listening")
	http.ListenAndServe(":3000", r)
}
