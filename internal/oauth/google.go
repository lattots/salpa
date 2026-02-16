package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/util"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (u googleUser) GetID() string {
	return u.ID
}

func (u googleUser) GetEmail() string {
	return u.Email
}

type googleProvider struct {
	// For production, userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	conf        *oauth2.Config
	userInfoURL string
}

const GoogleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

func NewGoogleProvider(conf *oauth2.Config, userInfoURL string) Provider {
	return &googleProvider{conf: conf, userInfoURL: userInfoURL}
}

func NewGoogleProviderFromConf(serviceDomain string, conf config.ProviderConfig) (Provider, error) {
	clientID := os.Getenv(conf.EnvironmentVariables["clientID"])
	clientSecret := os.Getenv(conf.EnvironmentVariables["clientSecret"])
	endpoint := google.Endpoint
	redirectURL := util.BuildURL(serviceDomain, "callback", "google")
	oauthConf := NewGoogleProviderConf(clientID, clientSecret, redirectURL, endpoint)

	return NewGoogleProvider(oauthConf, GoogleUserInfoURL), nil
}

func NewGoogleProviderConf(clientID, clientSecret, redirectURL string, endpoint oauth2.Endpoint) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     endpoint, // In production this will be google.endpoint
	}
}

func (p *googleProvider) GetAuthCodeURL(state string) string {
	return p.conf.AuthCodeURL(state)
}

func (p *googleProvider) ExchangeUserInfo(code string) (models.User, error) {
	googleToken, err := p.conf.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	client := p.conf.Client(context.Background(), googleToken)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user googleUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}

func CreateMockGoogleProvider() (Provider, func()) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/token":
			fmt.Fprintln(w, `{"access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600}`)
		case "/userinfo":
			fmt.Fprintln(w, `{"id": "12345", "email": "test-user@example.com"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	endpoint := oauth2.Endpoint{
		AuthURL:  ts.URL + "/auth",
		TokenURL: ts.URL + "/token",
	}
	conf := NewGoogleProviderConf("id", "secret", "http://localhost:8080/callback", endpoint)

	provider := NewGoogleProvider(conf, ts.URL+"/userinfo")

	return provider, ts.Close
}
