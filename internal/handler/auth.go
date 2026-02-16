package handler

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/oauth"
	"github.com/lattots/salpa/internal/token"
)

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		http.Error(w, "No return_to found in request", http.StatusBadRequest)
		return
	}

	authProvider, err := h.getAuthProvider(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "return_to",
		Value:    returnTo,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	state := generateStateCookie(w)
	url := authProvider.GetAuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	err := verifyRequestStateCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	authProvider, err := h.getAuthProvider(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	user, err := authProvider.ExchangeUserInfo(code)
	if err != nil {
		http.Error(w, "Error exchangin user info", http.StatusInternalServerError)
		log.Println("error exchangin user info with Google:", err)
		return
	}

	refreshToken, err := h.token.NewRefreshToken(user.GetID(), user.GetEmail())
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		log.Println("error creating access token:", err)
		return
	}

	accessToken, expiresAt, err := h.token.NewAccessToken(refreshToken.TokenID)
	if err != nil {
		http.Error(w, "Error creating access token", http.StatusInternalServerError)
		log.Println("error creating access token:", err)
		return
	}

	returnToCookie, err := r.Cookie("return_to")
	if err != nil {
		http.Error(w, "No return_to cookie found", http.StatusBadRequest)
		return
	}
	returnToURL := returnToCookie.Value
	if returnToURL == "" {
		http.Error(w, "Empty return_to URL found", http.StatusBadRequest)
		return
	}

	// This handles setting token cookies as well as removing return_to cookie from the response
	h.setRedirectCookies(w, r, accessToken, expiresAt, refreshToken)

	http.Redirect(w, r, returnToURL, http.StatusSeeOther)
}

func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Refresh token missing", http.StatusUnauthorized)
		return
	}

	newAccessToken, expiresAt, err := h.token.NewAccessToken(cookie.Value)
	if errors.Is(err, token.ErrTokenInvalid) {
		http.Error(w, "Refresh token invalid", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    newAccessToken,
		Path:     "/",
		Domain:   h.appDomain,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	pubASN1, _ := x509.MarshalPKIXPublicKey(h.token.AccessTokenPublic)
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	pem.Encode(w, pemBlock)
}

func (h *Handler) setRedirectCookies(
	w http.ResponseWriter,
	r *http.Request,
	accessToken string,
	accessTokenExpiresAt time.Time,
	refreshToken models.RefreshToken,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Domain:   h.appDomain,
		Expires:  accessTokenExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.TokenID,
		Path:     "/auth/refresh",
		Domain:   h.serviceDomain,
		Expires:  refreshToken.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:   "return_to",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func (h *Handler) getAuthProvider(r *http.Request) (oauth.Provider, error) {
	authProviderStr := r.PathValue("provider")
	if authProviderStr == "" {
		return nil, errors.New("No auth provider in request")
	}
	authProvider, ok := h.providers[authProviderStr]
	if !ok {
		return nil, errors.New("Unknown auth provider")
	}

	return authProvider, nil
}
