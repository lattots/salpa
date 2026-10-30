package oauth_test

import (
	"testing"

	"github.com/lattots/salpa/internal/oauth"
)

func TestGoogleLogin(t *testing.T) {
	provider, closeFunc := oauth.CreateMockGoogleProvider()
	defer closeFunc()

	_, err := provider.ExchangeUserInfo("some-fake-code")
	if err != nil {
		t.Fatalf("failed to exhange user info with auth provider: %s\n", err)
	}
}
