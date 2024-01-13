/*
Auth HTMX is a simple demonstration of OAuth2/OIDC in combination with HTMX, written in Go.
*/package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"embed"

	"github.com/Darkness4/auth-htmx/auth"
	internalwebauthn "github.com/Darkness4/auth-htmx/auth/webauthn"
	"github.com/Darkness4/auth-htmx/auth/webauthn/session"
	"github.com/Darkness4/auth-htmx/database"
	"github.com/Darkness4/auth-htmx/database/counter"
	"github.com/Darkness4/auth-htmx/database/user"
	"github.com/Darkness4/auth-htmx/handler"
	"github.com/Darkness4/auth-htmx/jwt"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/csrf"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

var (
	//go:embed pages/* components/* base.html base.htmx
	html      embed.FS
	version   = "dev"
	key       []byte
	jwtSecret string

	configPath string
	publicURL  string

	dbFile string
)

var app = &cli.App{
	Name:    "auth-htmx",
	Version: version,
	Usage:   "Demo of Auth and HTMX.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "csrf.secret",
			Usage: "A 32 bytes hex secret",
			Action: func(ctx *cli.Context, s string) error {
				data, err := hex.DecodeString(s)
				if err != nil {
					panic(err)
				}
				key = data
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
			Name:        "config.path",
			Usage:       "Path of the configuration file.",
			Destination: &configPath,
			Value:       "./config.yaml",
			Aliases:     []string{"c"},
			EnvVars:     []string{"CONFIG_PATH"},
		},
		&cli.StringFlag{
			Name:        "public-url",
			Usage:       "An URL pointing to the server.",
			Destination: &publicURL,
			Value:       "http://localhost:3000",
			EnvVars:     []string{"PUBLIC_URL"},
		},
		&cli.StringFlag{
			Name:        "db.path",
			Value:       "./db.sqlite3",
			Destination: &dbFile,
			Usage:       "SQLite3 database file path.",
			EnvVars:     []string{"DB_PATH"},
		},
	},
	Suggest: true,
	Action: func(cCtx *cli.Context) error {
		ctx := cCtx.Context
		log.Level(zerolog.DebugLevel)

		// Parse config
		var config auth.Config
		if err := func() error {
			file, err := os.Open(configPath)
			if err != nil {
				return err
			}
			defer file.Close()

			return yaml.NewDecoder(file).Decode(&config)
		}(); err != nil {
			return err
		}

		// JWT

		providers, err := auth.GenerateProviders(ctx, config, fmt.Sprintf("%s/callback", publicURL))
		if err != nil {
			return err
		}

		// Auth
		authService := auth.Auth{
			JWTSecret: jwt.Secret(jwtSecret),
			Providers: providers,
		}

		// Router
		r := chi.NewRouter()
		r.Use(hlog.NewHandler(log.Logger))
		r.Use(authService.Middleware)

		// Auth Guard
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, isAuth := auth.GetClaimsFromRequest(r)

				if !isAuth {
					switch r.URL.Path {
					case "/counter":
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
				}

				next.ServeHTTP(w, r)
			})
		})

		// DB
		d, err := sql.Open("sqlite", dbFile)
		if err != nil {
			log.Error().Err(err).Msg("db failed")
			return err
		}
		if err := database.InitialMigration(d); err != nil {
			log.Error().Err(err).Msg("db migration failed")
			return err
		}

		// Auth
		r.Get("/login", authService.Login())
		r.Get("/logout", authService.Logout())
		r.Get("/callback", authService.CallBack())

		u, err := url.Parse(publicURL)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to parse public URL")
		}

		webAuthn, err := webauthn.New(&webauthn.Config{
			RPDisplayName: "Auth HTMX",  // Display Name for your site
			RPID:          u.Hostname(), // Generally the domain name for your site
			RPOrigin:      publicURL,    // The origin URL for WebAuthn requests
		})
		if err != nil {
			panic(err)
		}

		webauthnS := internalwebauthn.New(
			webAuthn,
			user.NewRepository(d),
			session.NewInMemory(),
			jwt.Secret(jwtSecret),
		)

		if config.SelfHostUsers {
			r.Route("/webauthn", func(r chi.Router) {
				r.Route("/login", func(r chi.Router) {
					r.Get("/begin", webauthnS.BeginLogin())
					r.Post("/finish", webauthnS.FinishLogin())
				})
				r.Route("/register", func(r chi.Router) {
					r.Get("/begin", webauthnS.BeginRegistration())
					r.Post("/finish", webauthnS.FinishRegistration())
				})
			})
		}

		// Backend
		cr := counter.NewRepository(d)
		r.Post("/count", handler.Count(cr))

		// Pages rendering
		var renderFn http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Clean(r.URL.Path)
			path = filepath.Clean(fmt.Sprintf("pages/%s/page.tmpl", path))

			var userName, userID string
			if claims, ok := auth.GetClaimsFromRequest(r); ok {
				userName = claims.UserName
				userID = claims.UserID
			}

			// Check if SSR
			var base string
			if r.Header.Get("Hx-Request") != "true" {
				// Initial Rendering
				base = "base.html"
			} else {
				// SSR
				base = "base.htmx"
			}
			t, err := template.ParseFS(html, base, path, "components/*")
			if err != nil {
				// The page doesn't exist
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if err := t.ExecuteTemplate(w, "base", struct {
				UserName      string
				UserID        string
				CSRFToken     string
				Providers     map[string]auth.Provider
				SelfHostUsers bool
			}{
				UserName:      userName,
				UserID:        userID,
				CSRFToken:     csrf.Token(r),
				Providers:     providers,
				SelfHostUsers: config.SelfHostUsers,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
		r.Get("/*", renderFn)

		log.Info().Msg("listening")
		return http.ListenAndServe(":3000", csrf.Protect(key)(r))
	},
}

func main() {
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("app crashed")
	}
}
