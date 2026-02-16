package client

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/util"

	"github.com/golang-jwt/jwt/v5"
)

type httpClient struct {
	domain          string   // Domain of the auth service
	providers       []string // OAuth2 providers like Google, Microsoft, Apple...
	verificationKey ed25519.PublicKey
}

func NewHTTPClient(authDomain string, providers []string) (AuthClient, error) {
	if authDomain == "" {
		return nil, errors.New("no auth domain provided for client")
	}
	if len(providers) == 0 {
		return nil, errors.New("no providers")
	}
	verKey, err := getVerificationKey(authDomain)
	if err != nil {
		return nil, fmt.Errorf("couldn't get verification key: %w", err)
	}
	client := &httpClient{
		domain:          authDomain,
		providers:       providers,
		verificationKey: verKey,
	}
	return client, nil
}

func (c *httpClient) GetLoginURLs() []string {
	urls := make([]string, len(c.providers))
	for i := range c.providers {
		urls[i] = util.BuildURL(c.domain, "login", c.providers[i])
	}
	return urls
}

func (c *httpClient) VerifyToken(tokenStr string) (*models.UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &models.UserClaims{}, c.getVerificationKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing refresh token: %w", err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	claims := token.Claims.(*models.UserClaims)
	return claims, nil
}

func (c *httpClient) getVerificationKey(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
		return nil, errors.New("unexpected signing method")
	}
	return c.verificationKey, nil
}
