package oauth_test

import (
	"fmt"
	"testing"

	"github.com/lattots/salpa/internal/oauth"
)

func TestGoogleLogin(t *testing.T) {
	provider, closeFunc := oauth.CreateMockGoogleProvider()
	defer closeFunc()

	user, err := provider.ExchangeUserInfo("some-fake-code")
	if err != nil {
		t.Fatalf("failed to exhange user info with auth provider: %s\n", err)
	}

	fmt.Printf("Got user: %s - %s\n", user.GetID(), user.GetEmail())
}
