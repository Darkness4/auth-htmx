// Package webauthn handles WebAuthn related functionalities.
package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Darkness4/auth-htmx/auth/webauthn/session"
	"github.com/Darkness4/auth-htmx/database/user"
	"github.com/Darkness4/auth-htmx/jwt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog/log"
)

// Service prepares WebAuthn handlers.
type Service struct {
	webAuthn  *webauthn.WebAuthn
	jwtSecret jwt.Secret
	users     user.Repository
	store     session.Store
}

// New instanciates a Webauthn Service.
func New(
	webAuthn *webauthn.WebAuthn,
	users user.Repository,
	store session.Store,
	jwtSecret jwt.Secret,
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
		webAuthn:  webAuthn,
		users:     users,
		store:     store,
		jwtSecret: jwtSecret,
	}
}

// BeginLogin is the handler called to generate options for the user's authenticator.
func (s *Service) BeginLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
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

		_, _ = w.Write(o)
	}
}

// FinishLogin is the handler called after the user's authenticator sent its payload.
func (s *Service) FinishLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
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

		// At this point, we've confirmed the correct authenticator has been
		// provided and it passed the challenge we gave it. We now need to make
		// sure that the sign counter is higher than what we have stored to help
		// give assurance that this credential wasn't cloned.
		if credential.Authenticator.CloneWarning {
			log.Err(err).Msg("credential appears to be cloned")
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// If login was successful, update the credential object
		if err := s.users.UpdateCredential(r.Context(), credential); err != nil {
			log.Err(err).
				Any("user", user).
				Msg("user failed to update credential during finish login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-fetch
		user, err = s.users.Get(r.Context(), user.ID)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info().Any("credential", credential).Any("user", user).Msg("user logged")

		// Identity is now verified
		token, err := s.jwtSecret.GenerateToken(
			base64.RawURLEncoding.EncodeToString(user.ID),
			user.Name,
			"webauthn",
			jwt.WithCredentials(user.Credentials),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// BeginRegistration beings the webauthn flow.
//
// Based on the user identity, webauthn will generate options for the authenticator.
// We send the options over JSON (not very htmx).
func (s *Service) BeginRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
			return
		}
		user, err := s.users.GetOrCreateByName(r.Context(), name) // Find or create the new user
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(user.Credentials) > 0 {
			// The user has already been registered. We must login.
			http.Error(w, "the user is already registered", http.StatusForbidden)
			return
		}
		registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
			credCreationOpts.CredentialExcludeList = user.ExcludeCredentialDescriptorList()
		}
		options, session, err := s.webAuthn.BeginRegistration(user, registerOptions)
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

		_, _ = w.Write(o)
	}
}

// FinishRegistration finishes the webauthn flow.
//
// The user has created options based on the options. We fetch the registration
// session from the session store.
// We complete the registration.
func (s *Service) FinishRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "empty user name", http.StatusBadRequest)
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
		if err := s.users.AddCredential(r.Context(), user.ID, credential); err != nil {
			log.Err(err).Any("user", user).Msg("user failed to add credential during registration")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-fetch
		user, err = s.users.Get(r.Context(), user.ID)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info().Any("credential", credential).Any("user", user).Msg("user created")

		// Identity is now verified
		token, err := s.jwtSecret.GenerateToken(
			base64.RawURLEncoding.EncodeToString(user.ID),
			user.Name,
			"webauthn",
			jwt.WithCredentials(user.Credentials),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// BeginAddDevice beings the webauthn registration flow.
//
// Based on the user identity, webauthn will generate options for the authenticator.
// We send the options over JSON (not very htmx).
//
// Compared to BeginRegistration, BeginAddDevice uses the JWT to allow the registration.
func (s *Service) BeginAddDevice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "session not found", http.StatusForbidden)
			return
		}

		userID, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil {
			log.Err(err).Any("claims", claims).Msg("failed to parse claims")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := s.users.Get(r.Context(), userID) // Find or create the new user
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
			credCreationOpts.CredentialExcludeList = user.ExcludeCredentialDescriptorList()
		}
		options, session, err := s.webAuthn.BeginRegistration(user, registerOptions)
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

		_, _ = w.Write(o)
	}
}

// FinishAddDevice finishes the webauthn registration flow.
//
// The user has created options based on the options. We fetch the registration
// session from the session store.
// We complete the registration.
func (s *Service) FinishAddDevice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "session not found", http.StatusForbidden)
			return
		}

		userID, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil {
			log.Err(err).Any("claims", claims).Msg("failed to parse claims")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := s.users.Get(r.Context(), userID) // Find or create the new user
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
		if err := s.users.AddCredential(r.Context(), user.ID, credential); err != nil {
			log.Err(err).Any("user", user).Msg("user failed to add credential during registration")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-fetch
		user, err = s.users.Get(r.Context(), user.ID)
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Info().Any("credential", credential).Any("user", user).Msg("device added")

		// Identity is now verified
		token, err := s.jwtSecret.GenerateToken(
			base64.RawURLEncoding.EncodeToString(user.ID),
			user.Name,
			"webauthn",
			jwt.WithCredentials(user.Credentials),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cookie := &http.Cookie{
			Name:     jwt.TokenCookieKey,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(jwt.ExpiresDuration),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// DeleteDevice deletes a webauthn credential.
func (s *Service) DeleteDevice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		credential := r.URL.Query().Get("credential")
		if credential == "" {
			http.Error(w, "empty credential", http.StatusBadRequest)
			return
		}

		cred, err := base64.RawURLEncoding.DecodeString(credential)
		if err != nil {
			log.Err(err).Str("credential", credential).Msg("failed to parse credential")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		claims, ok := jwt.GetClaimsFromRequest(r)
		if !ok {
			http.Error(w, "session not found", http.StatusForbidden)
			return
		}

		userID, err := base64.RawURLEncoding.DecodeString(claims.ID)
		if err != nil {
			log.Err(err).Any("claims", claims).Msg("failed to parse claims")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := s.users.Get(r.Context(), userID) // Find or create the new user
		if err != nil {
			log.Err(err).Any("user", user).Msg("failed to fetch user")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(user.Credentials) <= 1 {
			http.Error(w, "last credential cannot be deleted", http.StatusForbidden)
			return
		}

		// If creation was successful, store the credential object
		if err := s.users.RemoveCredential(r.Context(), user.ID, cred); err != nil {
			log.Err(err).Any("user", user).Msg("user failed to remove credential")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
