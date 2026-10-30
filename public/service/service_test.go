package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/public/client"
)

type serviceTestAuthClient struct {
	claims *models.UserClaims
	err    error
}

func (c serviceTestAuthClient) GetLoginURLs() []string { return nil }
func (c serviceTestAuthClient) VerifyToken(string) (*models.UserClaims, error) {
	return c.claims, c.err
}

type serviceTestAuthorizer struct {
	level     string
	attribute string
	err       error
}

func (a serviceTestAuthorizer) GetLevel(string) (string, error) {
	return a.level, a.err
}

func (a serviceTestAuthorizer) GetAttribute(string, string) (string, error) {
	return a.attribute, a.err
}

func serviceTestClaims() *models.UserClaims {
	return &models.UserClaims{
		UserID:  "user-1",
		Email:   "user@example.test",
		Subject: "user-1",
	}
}

func serviceTestAuthenticatedRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "test-access-token",
	})
	return r
}

func TestAllowOnlyRejectsMissingToken(t *testing.T) {
	s := NewDefaultService(serviceTestAuthorizer{level: "admin"},
		serviceTestAuthClient{err: client.ErrTokenNotFound})
	called := false
	h := s.AllowOnly(func(http.ResponseWriter, *http.Request) { called = true }, []string{"admin"})
	w := httptest.NewRecorder()
	h(w, serviceTestAuthenticatedRequest(http.MethodGet, "/admin"))
	if w.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d called=%v, want 401 and handler not called", w.Code, called)
	}
}

func TestAllowOnlyRejectsInvalidToken(t *testing.T) {
	s := NewDefaultService(serviceTestAuthorizer{level: "admin"},
		serviceTestAuthClient{err: client.ErrInvalidToken})
	w := httptest.NewRecorder()
	s.AllowOnly(func(http.ResponseWriter, *http.Request) {}, []string{"admin"})(
		w, serviceTestAuthenticatedRequest(http.MethodGet, "/admin"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", w.Code)
	}
}

func TestAllowOnlyRejectsInsufficientRole(t *testing.T) {
	s := NewDefaultService(serviceTestAuthorizer{level: "user"},
		serviceTestAuthClient{claims: serviceTestClaims()})
	called := false
	w := httptest.NewRecorder()
	s.AllowOnly(func(http.ResponseWriter, *http.Request) { called = true }, []string{"admin"})(
		w, serviceTestAuthenticatedRequest(http.MethodGet, "/admin"))
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v, want 403 and handler not called", w.Code, called)
	}
}

func TestAllowOnlyPassesAuthorizedRequest(t *testing.T) {
	s := NewDefaultService(serviceTestAuthorizer{level: "admin"},
		serviceTestAuthClient{claims: serviceTestClaims()})
	called := false
	w := httptest.NewRecorder()
	s.AllowOnly(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}, []string{"admin"})(w, serviceTestAuthenticatedRequest(http.MethodGet, "/admin"))
	if w.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d called=%v, want 204 and handler called", w.Code, called)
	}
}

func TestAllowPathValRequiresMatchingPathValue(t *testing.T) {
	s := NewDefaultService(serviceTestAuthorizer{attribute: "user-1"},
		serviceTestAuthClient{claims: serviceTestClaims()})

	t.Run("matching", func(t *testing.T) {
		r := serviceTestAuthenticatedRequest(http.MethodGet, "/users/user-1")
		r.SetPathValue("userID", "user-1")
		w := httptest.NewRecorder()
		called := false
		s.AllowPathVal(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}, "userID")(w, r)
		if w.Code != http.StatusNoContent || !called {
			t.Fatalf("status=%d called=%v", w.Code, called)
		}
	})

	t.Run("different user", func(t *testing.T) {
		r := serviceTestAuthenticatedRequest(http.MethodGet, "/users/user-2")
		r.SetPathValue("userID", "user-2")
		w := httptest.NewRecorder()
		s.AllowPathVal(func(http.ResponseWriter, *http.Request) {}, "userID")(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", w.Code)
		}
	})

	t.Run("missing path value", func(t *testing.T) {
		r := serviceTestAuthenticatedRequest(http.MethodGet, "/users/")
		w := httptest.NewRecorder()
		s.AllowPathVal(func(http.ResponseWriter, *http.Request) {}, "userID")(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", w.Code)
		}
	})
}

func TestAllowOnlyTreatsUnknownVerificationErrorsAsServerErrors(t *testing.T) {
	s := NewDefaultService(serviceTestAuthorizer{level: "admin"},
		serviceTestAuthClient{err: errors.New("verification key unavailable")})
	w := httptest.NewRecorder()
	s.AllowOnly(func(http.ResponseWriter, *http.Request) {}, []string{"admin"})(
		w, serviceTestAuthenticatedRequest(http.MethodGet, "/admin"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", w.Code)
	}
}
