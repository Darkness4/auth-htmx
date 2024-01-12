package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Darkness4/auth-htmx/database/user"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
)

type Service struct {
	webAuthn webauthn.WebAuthn
	users    user.Repository
}

func New(
	webAuthn webauthn.WebAuthn,
	users user.Repository,
) *Service {
	if users == nil {
		panic("users is nil")
	}
	return &Service{
		webAuthn: webAuthn,
		users:    users,
	}
}

func (s *Service) BeginLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
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
		datastore.SaveSession(session)

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
		name := chi.URLParam(r, "name")
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session := datastore.GetSession()

		credential, err := s.webAuthn.FinishLogin(user, session, r)
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
		datastore.SaveUser(user)

		fmt.Fprintln(w, "Login Success")
	}
}

func (s *Service) BeginRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		user, err := s.users.GetByName(r.Context(), name) // Find or create the new user
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// TODO: create user
		options, session, err := s.webAuthn.BeginRegistration(user)
		if err != nil {
			log.Err(err).Any("user", user).Msg("user failed to begin registration")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store the session values
		datastore.SaveSession(session)

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
		name := chi.URLParam(r, "name")
		user, err := s.users.GetByName(r.Context(), name)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the session data stored from the function above
		session := datastore.GetSession()

		credential, err := s.webAuthn.FinishRegistration(user, session, r)
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
		datastore.SaveUser(user)

		log.Info().Any("user", user).Msg("user created")
		fmt.Fprintln(w, "Registration Success")
	}
}
