package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/oauth"
	"github.com/lattots/salpa/internal/token"
)

type handlerTestUser struct {
	id    string
	email string
}

func (u handlerTestUser) GetID() string    { return u.id }
func (u handlerTestUser) GetEmail() string { return u.email }

type handlerTestSession struct {
	userID string
	email  string
	expiry time.Time
}

type handlerTestStore struct {
	mu       sync.Mutex
	sessions map[string]handlerTestSession
}

func newHandlerTestStore() *handlerTestStore {
	return &handlerTestStore{sessions: make(map[string]handlerTestSession)}
}

func (s *handlerTestStore) Add(_ context.Context, tkn models.RefreshToken, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[tkn.TokenID] = handlerTestSession{userID: tkn.UserID, email: email, expiry: tkn.ExpiresAt}
	return nil
}

func (s *handlerTestStore) Check(_ context.Context, id string) (bool, models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || !session.expiry.After(time.Now()) {
		return false, nil, nil
	}
	return true, handlerTestUser{id: session.userID, email: session.email}, nil
}

func (s *handlerTestStore) Remove(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *handlerTestStore) RemoveAllForUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.userID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *handlerTestStore) Close() error { return nil }

func (s *handlerTestStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

type handlerTestProvider struct {
	mu          sync.Mutex
	authURL     string
	user        models.User
	exchangeErr error
	gotCode     string
}

func (p *handlerTestProvider) GetAuthCodeURL(state string) string {
	u, _ := url.Parse(p.authURL)
	q := u.Query()
	q.Set("oauth_state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

func (p *handlerTestProvider) ExchangeUserInfo(code string) (models.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gotCode = code
	return p.user, p.exchangeErr
}

func newHandlerTestFixture(t *testing.T) (*Handler, *handlerTestStore, *handlerTestProvider) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	store := newHandlerTestStore()
	provider := &handlerTestProvider{
		mu:      sync.Mutex{},
		authURL: "https://identity.example.test/authorize",
		user:    handlerTestUser{id: "user-123", email: "user@example.test"},
	}
	manager := token.NewManager(store, privateKey)
	h := &Handler{
		providers: map[string]oauth.Provider{"google": provider},
		token:     manager,
		appDomain: "app.example.test",
	}
	return h, store, provider
}

func TestHandleLoginUnknownProviderReturns400WithoutPanicking(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/auth/login/unknown?return_to=https%3A%2F%2Fapp.example.test%2F", nil)
	r.SetPathValue("provider", "unknown")
	w := httptest.NewRecorder()

	h.HandleLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if w.Header().Get("Location") != "" {
		t.Fatalf("unexpected redirect to %q", w.Header().Get("Location"))
	}
}

func TestHandleLoginRejectsUntrustedReturnTo(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	r := httptest.NewRequest(http.MethodGet,
		"/auth/login/google?return_to="+url.QueryEscape("https://attacker.example.test/collect"), nil)
	r.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	h.HandleLogin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("untrusted return_to accepted: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleLoginSetsCallbackUsableStateCookie(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	returnTo := "https://app.example.test/dashboard"
	r := httptest.NewRequest(http.MethodGet,
		"/auth/login/google?return_to="+url.QueryEscape(returnTo), nil)
	r.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	h.HandleLogin(w, r)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusTemporaryRedirect, w.Body.String())
	}
	var stateCookie, returnCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "return_to":
			returnCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie was not set")
	}
	if stateCookie.Value == "" {
		t.Fatal("state cookie is empty")
	}
	if !stateCookie.Secure || !stateCookie.HttpOnly || stateCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("unsafe state cookie attributes: Secure=%v HttpOnly=%v SameSite=%v",
			stateCookie.Secure, stateCookie.HttpOnly, stateCookie.SameSite)
	}
	if stateCookie.Path == "" || !strings.HasPrefix("/auth/callback/google", stateCookie.Path) {
		t.Errorf("state cookie Path=%q does not cover /auth/callback/google", stateCookie.Path)
	}
	if returnCookie == nil || returnCookie.Value != returnTo {
		t.Fatalf("return_to cookie = %#v, want value %q", returnCookie, returnTo)
	}
	if !returnCookie.Secure || !returnCookie.HttpOnly || returnCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("unsafe return_to cookie attributes: %#v", returnCookie)
	}
}

func TestHandleCallbackUnknownProviderReturns400WithoutPanicking(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback/unknown?code=authorization-code&state=known-state", nil)
	r.SetPathValue("provider", "unknown")
	r.AddCookie(&http.Cookie{Name: "oauth_state", Value: "known-state"})
	r.AddCookie(&http.Cookie{Name: "return_to", Value: "https://app.example.test/"})
	w := httptest.NewRecorder()

	h.HandleCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleCallbackRejectsMismatchedStateBeforeExchangingCode(t *testing.T) {
	h, sessions, provider := newHandlerTestFixture(t)
	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback/google?code=authorization-code&state=from-query", nil)
	r.SetPathValue("provider", "google")
	r.AddCookie(&http.Cookie{Name: "state", Value: "different-value"})
	w := httptest.NewRecorder()

	h.HandleCallback(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if provider.gotCode != "" {
		t.Fatalf("provider exchanged code %q despite invalid state", provider.gotCode)
	}
	if got := sessions.count(); got != 0 {
		t.Fatalf("created %d session(s) despite invalid state", got)
	}
}

func TestHandleCallbackChecksReturnToBeforeCreatingSession(t *testing.T) {
	h, sessions, _ := newHandlerTestFixture(t)
	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback/google?code=authorization-code&state=known-state", nil)
	r.SetPathValue("provider", "google")
	r.AddCookie(&http.Cookie{Name: "oauth_state", Value: "known-state"})
	w := httptest.NewRecorder()

	h.HandleCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if got := sessions.count(); got != 0 {
		t.Fatalf("created %d orphan session(s) without a return_to cookie", got)
	}
}

func TestHandleCallbackGETRouteSupportsDefaultOAuthCallback(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	mux := http.NewServeMux()
	h.SetRoutes(mux)

	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback/google?code=authorization-code&state=known-state", nil)
	r.AddCookie(&http.Cookie{Name: "oauth_state", Value: "known-state"})
	r.AddCookie(&http.Cookie{Name: "return_to", Value: "https://app.example.test/"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("GET OAuth callback status = %d, want %d; body: %s",
			w.Code, http.StatusSeeOther, w.Body.String())
	}
}

func TestHandleCallbackSuccessIssuesTokensAndRedirects(t *testing.T) {
	h, sessions, provider := newHandlerTestFixture(t)
	returnTo := "https://app.example.test/after-login"
	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback/google?code=authorization-code&state=known-state", nil)
	r.SetPathValue("provider", "google")
	r.AddCookie(&http.Cookie{Name: "oauth_state", Value: "known-state"})
	r.AddCookie(&http.Cookie{Name: "return_to", Value: returnTo})
	w := httptest.NewRecorder()

	h.HandleCallback(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusSeeOther, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != returnTo {
		t.Fatalf("Location = %q, want %q", got, returnTo)
	}
	if provider.gotCode != "authorization-code" {
		t.Fatalf("exchanged code = %q", provider.gotCode)
	}
	if sessions.count() != 1 {
		t.Fatalf("session count = %d, want 1", sessions.count())
	}

	var access, refresh *http.Cookie
	stateExpired := false
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "access_token":
			access = c
		case "refresh_token":
			refresh = c
		case "oauth_state":
			stateExpired = c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(time.Now()))
		}
	}
	if !stateExpired {
		t.Error("successful callback did not consume/expire the OAuth state cookie")
	}
	if access == nil || access.Value == "" {
		t.Fatal("access_token cookie missing")
	}
	if refresh == nil || refresh.Value == "" {
		t.Fatal("refresh_token cookie missing")
	}
	if access.Domain != h.appDomain {
		t.Errorf("access cookie Domain=%q, want %q", access.Domain, h.appDomain)
	}
	if access.Path != "/" || refresh.Path != "/auth" {
		t.Errorf("unexpected cookie paths: access=%q refresh=%q", access.Path, refresh.Path)
	}
	if _, err := h.token.VerifyAccessToken(access.Value); err != nil {
		t.Fatalf("issued access token does not verify: %v", err)
	}
}

func TestHandleRefreshIssuesNewAccessCookie(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	refresh, err := h.token.NewRefreshToken("user-123", "user@example.test")
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "refresh_token", Value: refresh.TokenID})
	r.Header.Set("Origin", "https://app.example.test")
	w := httptest.NewRecorder()
	h.HandleRefresh(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
	var access *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "access_token" {
			access = c
		}
	}
	if access == nil || access.Value == "" {
		t.Fatal("refresh response did not set access_token")
	}
	if _, err := h.token.VerifyAccessToken(access.Value); err != nil {
		t.Fatalf("refreshed access token does not verify: %v", err)
	}
}

func TestHandleRefreshRejectsUntrustedOrigin(t *testing.T) {
	h, _, _ := newHandlerTestFixture(t)
	refresh, err := h.token.NewRefreshToken("user-123", "user@example.test")
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	r.Header.Set("Origin", "https://attacker.example.test")
	r.AddCookie(&http.Cookie{Name: "refresh_token", Value: refresh.TokenID})
	w := httptest.NewRecorder()
	h.HandleRefresh(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin refresh status = %d, want %d", w.Code, http.StatusForbidden)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "access_token" && c.Value != "" {
			t.Fatal("cross-origin refresh issued a new access token")
		}
	}
}

func TestLogoutRouteRevokesSessionAndClearsCookies(t *testing.T) {
	h, sessions, _ := newHandlerTestFixture(t)
	refresh, err := h.token.NewRefreshToken("user-123", "user@example.test")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	h.SetRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(&http.Cookie{Name: "refresh_token", Value: refresh.TokenID})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d; body: %s", w.Code, http.StatusNoContent, w.Body.String())
	}
	if sessions.count() != 0 {
		t.Fatalf("logout left %d active session(s)", sessions.count())
	}
	expiredCookies := make(map[string]bool)
	for _, c := range w.Result().Cookies() {
		if c.Name != "access_token" && c.Name != "refresh_token" {
			continue
		}
		expiredCookies[c.Name] = c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(time.Now()))
	}
	for _, name := range []string{"access_token", "refresh_token"} {
		if !expiredCookies[name] {
			t.Errorf("logout did not expire %q cookie", name)
		}
	}
}

func TestHandleCallbackProviderFailureDoesNotCreateSession(t *testing.T) {
	h, sessions, provider := newHandlerTestFixture(t)
	provider.exchangeErr = context.DeadlineExceeded
	r := httptest.NewRequest(http.MethodGet,
		"/auth/callback/google?code=authorization-code&state=known-state", nil)
	r.SetPathValue("provider", "google")
	r.AddCookie(&http.Cookie{Name: "oauth_state", Value: "known-state"})
	r.AddCookie(&http.Cookie{Name: "return_to", Value: "https://app.example.test/"})
	w := httptest.NewRecorder()

	h.HandleCallback(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if sessions.count() != 0 {
		t.Fatalf("created %d sessions after provider failure", sessions.count())
	}
}
