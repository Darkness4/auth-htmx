package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

const TokenCookieKey = "session_token"
const expiresDuration = 24 * time.Hour

type ClaimsContextKey struct{}

type Claims struct {
	jwt.RegisteredClaims
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
}

type Service struct {
	SecretKey []byte
}

func (s *Service) GenerateToken(userID string, userName string) (string, error) {
	// Create the token claims
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresDuration)),
		},
		UserID:   userID,
		UserName: userName,
	}

	// Create the token object
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(s.SecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *Service) VerifyToken(tokenString string) (*Claims, error) {
	// Parse the token
	var claims Claims
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			// Make sure the signing method is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}

			// Return the secret key for validation
			return []byte(s.SecretKey), nil
		},
	)
	if err != nil {
		return nil, err
	}

	// Verify and return the claims
	if token.Valid {
		return &claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *Service) GenerateTokenAndStore(
	w http.ResponseWriter,
	userID string,
	userName string,
) error {
	token, err := s.GenerateToken(userID, userName)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     TokenCookieKey,
		Value:    token,
		Expires:  time.Now().Add(expiresDuration),
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (s *Service) AuthMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT token from the request header
		cookie, err := r.Cookie(TokenCookieKey)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Verify the JWT token
		claims, err := s.VerifyToken(cookie.Value)
		if err != nil {
			log.Error().AnErr("err", err).Msg("token verification failed")
			next.ServeHTTP(w, r)
			return
		}

		// Store the claims in the request context for further use
		ctx := context.WithValue(r.Context(), ClaimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
