package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lattots/salpa/internal/config"
	"golang.org/x/oauth2"
)

func newGoogleProviderForTest(t *testing.T, userInfoStatus int, userInfoBody string) Provider {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(userInfoStatus)
			fmt.Fprint(w, userInfoBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	conf := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://auth.example.test/auth/callback/google",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/authorize",
			TokenURL: server.URL + "/token",
		},
	}
	return NewGoogleProvider(conf, server.URL+"/userinfo")
}

func TestGoogleProviderRejectsNon2xxUserInfoResponse(t *testing.T) {
	provider := newGoogleProviderForTest(t, http.StatusUnauthorized,
		`{"id":"google-user-1","email":"user@example.test"}`)
	if _, err := provider.ExchangeUserInfo("valid-code"); err == nil {
		t.Fatal("accepted user-info response with HTTP 401")
	}
}

func TestGoogleProviderRejectsMissingIdentityFields(t *testing.T) {
	provider := newGoogleProviderForTest(t, http.StatusOK, `{"id":"google-user-1"}`)
	if _, err := provider.ExchangeUserInfo("valid-code"); err == nil {
		t.Fatal("accepted a user-info response without an email address")
	}
}

func TestCreateProvidersRejectsMissingActiveProviderCredentials(t *testing.T) {
	t.Setenv("SALPA_EMPTY_GOOGLE_CLIENT_ID", "")
	t.Setenv("SALPA_EMPTY_GOOGLE_CLIENT_SECRET", "")
	providers := CreateProviders("https://auth.example.test", map[string]config.ProviderConfig{
		"google": {
			Active: true,
			EnvironmentVariables: map[string]string{
				"clientID":     "SALPA_EMPTY_GOOGLE_CLIENT_ID",
				"clientSecret": "SALPA_EMPTY_GOOGLE_CLIENT_SECRET",
			},
		},
	})
	if _, ok := providers["google"]; ok {
		t.Fatal("registered an active provider without client credentials")
	}
}

func TestCreateProvidersSkipsInactiveProvider(t *testing.T) {
	providers := CreateProviders("https://auth.example.test", map[string]config.ProviderConfig{
		"google": {
			Active: false,
			EnvironmentVariables: map[string]string{
				"clientID":     "SALPA_TEST_GOOGLE_CLIENT_ID",
				"clientSecret": "SALPA_TEST_GOOGLE_CLIENT_SECRET",
			},
		},
	})
	if _, ok := providers["google"]; ok {
		t.Fatal("inactive Google provider was registered")
	}
}
