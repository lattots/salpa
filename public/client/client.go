package client

import (
	"errors"
	"net/http"

	"github.com/lattots/salpa/internal/models"
)

type AuthClient interface {
	GetLoginURLs() []string
	VerifyToken(string) (*models.UserClaims, error)
}

var (
	ErrInvalidToken  = errors.New("access token is invalid")
	ErrTokenNotFound = errors.New("no access token found in request header")
)

func GetClaims(client AuthClient, r *http.Request) (*models.UserClaims, error) {
	token := GetToken(r)
	if token == "" {
		return nil, ErrTokenNotFound
	}

	claims, err := client.VerifyToken(token)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func GetToken(r *http.Request) string {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}
