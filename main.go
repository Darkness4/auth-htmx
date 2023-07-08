package main

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"embed"

	"github.com/Darkness4/auth-htmx/handler"
	"github.com/Darkness4/auth-htmx/utils"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var (
	//go:embed pages/* components/* base.html base.htmx
	html      embed.FS
	version   = "dev"
	key       []byte
	jwtSecret string

	oauthClientID       string
	oauthSecret         string
	oauthAuthorizeURL   string
	oauthURL            string
	oauthAccessTokenURL string
)

var app = &cli.App{
	Name:    "auth-htmx",
	Version: version,
	Usage:   "Overwatch the job scheduling and register the compute to the Deepsquare Grid.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "csrf.secret",
			Usage: "A 32 bytes hex secret",
			Action: func(ctx *cli.Context, s string) error {
				key = utils.Must(hex.DecodeString(s))
				return nil
			},
			EnvVars: []string{"CSRF_SECRET"},
		},
		&cli.StringFlag{
			Name:        "jwt.secret",
			Usage:       "A unique string secret",
			Destination: &jwtSecret,
			EnvVars:     []string{"JWT_SECRET"},
		},
		&cli.StringFlag{
			Name:        "oauth.clientid",
			Usage:       "A unique string secret",
			Destination: &oauthClientID,
			EnvVars:     []string{"OAUTH_CLIENTID"},
		},
		&cli.StringFlag{
			Name:        "oauth.secret",
			Usage:       "A unique string secret",
			Destination: &oauthSecret,
			EnvVars:     []string{"OAUTH_SECRET"},
		},
		&cli.StringFlag{
			Name:        "oauth.authorize.url",
			Usage:       "An URL to request an access key.",
			Destination: &oauthAuthorizeURL,
			Value:       "https://github.com/login/oauth/authorize",
			EnvVars:     []string{"OAUTH_AUTHORIZE_URL"},
		},
		&cli.StringFlag{
			Name:        "oauth.accesstoken.url",
			Usage:       "An URL to fetch the access token.",
			Destination: &oauthAccessTokenURL,
			Value:       "https://github.com/login/oauth/access_token",
			EnvVars:     []string{"OAUTH_ACCESSTOKEN_URL"},
		},
		&cli.StringFlag{
			Name:        "oauth.url",
			Usage:       "An URL pointing to the server.",
			Destination: &oauthURL,
			Value:       "http://localhost:3000",
			EnvVars:     []string{"OAUTH_URL"},
		},
	},
	Suggest: true,
	Action: func(cCtx *cli.Context) error {
		log.Level(zerolog.DebugLevel)
		r := chi.NewRouter()
		r.Use(hlog.NewHandler(log.Logger))

		auth := handler.AuthenticationService{
			AuthorizationURL: oauthAuthorizeURL,
			AccessTokenURL:   oauthAccessTokenURL,
			ClientID:         oauthClientID,
			ClientSecret:     oauthSecret,
			RedirectURI:      fmt.Sprintf("%s/callback", oauthURL),
		}

		// SSR
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Clean(r.URL.Path)
			path = filepath.Clean(fmt.Sprintf("pages/%s/page.tmpl", path))

			if r.Header.Get("Hx-Request") != "true" {
				// Initial Rendering
				t, err := template.ParseFS(html, "base.html", path, "components/*")
				if err != nil {
					// The page doesn't exist
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, "404 Page Not Found")
					return
				}
				t.ExecuteTemplate(w, "base", nil)
			} else {
				// SSR
				t := template.Must(
					template.ParseFS(html, "base.htmx", path, "components/*"),
				)
				t.ExecuteTemplate(w, "base", nil)
			}
		})

		// Auth
		r.Get("/login", auth.Login())
		r.Get("/callback", auth.CallBack())

		// Backend
		r.Post("/count", handler.Count)
		log.Info().Msg("listening")
		return http.ListenAndServe(":3000", csrf.Protect(key)(r))
	},
}

func main() {
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")
	if err := app.Run(os.Args); err != nil {
		log.Fatal().AnErr("err", err).Msg("app crashed")
	}
}
