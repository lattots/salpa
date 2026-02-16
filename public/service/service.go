package service

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"

	"github.com/lattots/salpa/public/client"
)

type AuthService interface {
	// Allow access based on user security level (only allow {admin} or {admin, user})
	AllowOnly(handler http.HandlerFunc, securityLevels []string) http.HandlerFunc

	// Allow access based on a path value (email, user ID, name...)
	// Path value name must match the attribute name in Authorizer
	AllowPathVal(handler http.HandlerFunc, pathValName string) http.HandlerFunc
}

type DefaultAuthService struct {
	authorizer Authorizer
	authClient client.AuthClient
}

func NewDefaultService(authorizer Authorizer, authClient client.AuthClient) *DefaultAuthService {
	return &DefaultAuthService{
		authorizer: authorizer,
		authClient: authClient,
	}
}

func (s *DefaultAuthService) AllowOnly(handler http.HandlerFunc, securityLevels []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userClaims, err := client.GetClaims(s.authClient, r)
		if errors.Is(err, client.ErrTokenNotFound) {
			http.Error(w, "user is not authenticated", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, client.ErrInvalidToken) {
			http.Error(w, "access token is invalid", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("failed to get user claims: %s\n", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		userLevel, err := s.authorizer.GetLevel(userClaims.Email)
		if err != nil {
			log.Printf("failed to get user security level: %s\n", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if !slices.Contains(securityLevels, userLevel) {
			http.Error(w, "user is not allowed to access this resource", http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}

func (s *DefaultAuthService) AllowPathVal(handler http.HandlerFunc, pathValName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userClaims, err := client.GetClaims(s.authClient, r)
		if errors.Is(err, client.ErrTokenNotFound) {
			http.Error(w, "user is not authenticated", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, client.ErrInvalidToken) {
			http.Error(w, "access token is invalid", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("failed to get user claims: %s\n", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		userVal, err := s.authorizer.GetAttribute(pathValName, userClaims.Email)
		if err != nil {
			log.Printf("failed to get user attribute: %s\n", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		pathVal := r.PathValue(pathValName)
		if pathVal == "" {
			http.Error(w, fmt.Sprintf("%s is not set in query path", pathValName), http.StatusBadRequest)
			return
		}

		if userVal != pathVal {
			http.Error(w, "user is not allowed to access this resource", http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}

// Authorizer interface to be implemented by user application.
// This is most likely going to be a database that maps user emails to user attributes.
type Authorizer interface {
	// Get user security level based on user email
	GetLevel(email string) (string, error)

	// Get an arbitrary user attribute based on user email (user ID, name, username...)
	GetAttribute(attributeName, email string) (string, error)
}
