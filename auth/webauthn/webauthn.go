package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Darkness4/auth-htmx/auth/webauthn/session"
	"github.com/Darkness4/auth-htmx/database/user"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
)

type Service struct {
	webAuthn *webauthn.WebAuthn
	users    user.Repository
	store    session.Store
}

func New(
	webAuthn *webauthn.WebAuthn,
	users user.Repository,
	store session.Store,
) *Service {
	if webAuthn == nil {
		panic("webAuthn is nil")
	}
	if users == nil {
		panic("users is nil")
	}
	if store == nil {
		panic("store is nil")
	}
	return &Service{
		webAuthn: webAuthn,
		users:    users,
		store:    store,
	}
}

func (s *Service) BeginLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "no name passed as query params", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		options, session, err := s.webAuthn.BeginLogin(user)
		if err != nil {
			log.Err(err).Any("user", user).Msg("user failed to begin login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store the session values
		if err := s.store.Save(r.Context(), session); err != nil {
			// Maybe a Fatal or Panic should be user here.
			log.Err(err).Any("user", user).Msg("failed to save session in store")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		o, err := json.Marshal(options)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to respond")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(o)
	}
}

func (s *Service) FinishLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "no name passed as query params", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session, err := s.store.Get(r.Context(), user.ID)
		if err != nil {
			// Maybe a Fatal or Panic should be user here.
			log.Err(err).Any("user", user).Msg("failed to save session in store")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		credential, err := s.webAuthn.FinishLogin(user, *session, r)
		if err != nil {
			log.Err(err).Any("user", user).Msg("user failed to finish login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Handle credential.Authenticator.CloneWarning

		// If login was successful, update the credential object
		if err := s.users.UpdateCredential(r.Context(), credential); err != nil {
			log.Err(err).
				Any("user", user).
				Msg("user failed to update credential during finish login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "Login Success")
	}
}

func (s *Service) BeginRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "no name passed as query params", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetOrCreateByName(r.Context(), name) // Find or create the new user
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		options, session, err := s.webAuthn.BeginRegistration(user)
		if err != nil {
			log.Err(err).Any("user", user).Msg("user failed to begin registration")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store the session values
		if err := s.store.Save(r.Context(), session); err != nil {
			// Maybe a Fatal or Panic should be user here.
			log.Err(err).Any("user", user).Msg("failed to save session in store")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		o, err := json.Marshal(options)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to respond")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(o)
	}
}

func (s *Service) FinishRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "no name passed as query params", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session, err := s.store.Get(r.Context(), user.ID)
		if err != nil {
			// Maybe a Fatal or Panic should be user here.
			log.Err(err).Any("user", user).Msg("failed to save session in store")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		credential, err := s.webAuthn.FinishRegistration(user, *session, r)
		if err != nil {
			log.Err(err).Any("user", user).Msg("user failed to finish registration")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If creation was successful, store the credential object
		// Pseudocode to add the user credential.
		if err := s.users.AddCredential(r.Context(), user.ID, credential); err != nil {
			log.Err(err).Any("user", user).Msg("user failed to add credential during registration")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info().Any("user", user).Msg("user created")
		fmt.Fprintln(w, "Registration Success")
	}
}
