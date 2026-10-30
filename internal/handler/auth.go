package handler

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
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

	returnURL, err := url.Parse(returnTo)
	if err != nil || !h.isValidReturnDomain(returnURL) {
		http.Error(w, "return_to parameter is not valid URL", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "return_to",
		Value:    returnTo,
		Path:     "/auth",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	authProvider, err := h.getAuthProvider(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// state token is used to verify that the callback request redirected from
	// Google is done by the same browser that initiated the authentication.
	// It is set to both URL query parameter and http only cookie so it can be
	// verified later in the callback.
	state := generateStateToken()
	url := authProvider.GetAuthCodeURL(state)

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/auth",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	err := verifyRequestStateCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/auth",
		MaxAge: -1,
	})

	returnToURL, err, status := h.parseReturnToAddress(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	authProvider, err := h.getAuthProvider(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wantedURI := fmt.Sprintf("/auth/callback/%s", r.PathValue("provider"))
	if r.URL.Path != wantedURI {
		http.Error(w, "Invalid callback URI", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
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

	// This handles setting token cookies as well as removing return_to cookie from the response
	h.setRedirectCookies(w, accessToken, expiresAt, refreshToken)

	http.Redirect(w, r, returnToURL, http.StatusSeeOther)
}

func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if !h.isValidSource(r) {
		http.Error(w, "Untrusted source", http.StatusForbidden)
		return
	}
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

func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Refresh token missing", http.StatusUnauthorized)
		return
	}

	refreshToken := models.RefreshToken{
		TokenID: cookie.Value,
	}

	h.token.RemoveRefreshToken(refreshToken)

	http.SetCookie(w, &http.Cookie{
		Name:   "refresh_token",
		Value:  "",
		Path:   "/auth",
		MaxAge: -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:   "access_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
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
		Path:     "/auth",
		Domain:   h.appDomain,
		Expires:  refreshToken.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:   "return_to",
		Value:  "",
		Path:   "/auth",
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

func (h *Handler) isValidReturnDomain(u *url.URL) bool {
	return u != nil &&
		u.IsAbs() &&
		u.Scheme == "https" &&
		u.User == nil &&
		u.Hostname() == h.appDomain &&
		u.Fragment == ""
}

// isValidSource checks whether the request originated from the application
func (h *Handler) isValidSource(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return u.Scheme == "https" &&
		u.Hostname() == h.appDomain &&
		u.Port() == ""
}

func (h *Handler) parseReturnToAddress(r *http.Request) (string, error, int) {
	returnToCookie, err := r.Cookie("return_to")
	if err != nil {
		return "", fmt.Errorf("No return_to cookie found"), http.StatusBadRequest
	}
	returnToString := returnToCookie.Value
	if returnToString == "" {
		return "", fmt.Errorf("Empty return_to URL found"), http.StatusBadRequest
	}
	returnToURL, err := url.Parse(returnToString)
	if err != nil || returnToURL.Hostname() != h.appDomain {
		return "", fmt.Errorf("Invalid return_to adderss"), http.StatusBadRequest
	}
	return returnToString, nil, 0
}
