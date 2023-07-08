package main

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"embed"

	"github.com/Darkness4/auth-htmx/handler"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

//go:embed pages/* base.html base.htmx
var html embed.FS

func main() {
	log.Level(zerolog.DebugLevel)
	r := chi.NewRouter()
	r.Use(hlog.NewHandler(log.Logger))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Clean(r.URL.Path)
		path = filepath.Clean(fmt.Sprintf("pages/%s/page.tmpl", path))

		if r.Header.Get("Hx-Request") != "true" {
			t := template.Must(
				template.ParseFS(html, "base.html", path),
			)
			t.ExecuteTemplate(w, "base", nil)
		} else {
			t := template.Must(
				template.ParseFS(html, "base.htmx", path),
			)
			t.ExecuteTemplate(w, "base", nil)
		}

	})
	r.Post("/count", handler.Count)
	log.Info().Msg("listening")
	http.ListenAndServe(":3000", r)
}
