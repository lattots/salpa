package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

func generateStateCookie(w http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	cookie := http.Cookie{
		Name:     "state",
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	return state
}

var (
	ErrNoStateCookie      = errors.New("Cookie missing: no state cookie in request")
	ErrInvalidStateCookie = errors.New("Invalid cookie: state cookie doesn't match the query parameter")
)

func verifyRequestStateCookie(r *http.Request) error {
	cookie, err := r.Cookie("state")
	if err != nil {
		return ErrNoStateCookie
	}

	param := r.FormValue("state")

	if cookie.Value != param {
		return ErrInvalidStateCookie
	}
	return nil
}
