package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
)

func generateStateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	return state
}

var (
	ErrNoStateCookie      = errors.New("Cookie missing: no state cookie in request")
	ErrInvalidStateCookie = errors.New("Invalid cookie: state cookie doesn't match the query parameter")
)

func verifyRequestStateCookie(r *http.Request) error {
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		return ErrNoStateCookie
	}

	param := r.FormValue("state")

	if cookie.Value != param {
		return ErrInvalidStateCookie
	}
	return nil
}
