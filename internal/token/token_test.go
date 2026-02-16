package token_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"github.com/lattots/salpa/internal/token"
	"github.com/lattots/salpa/internal/token/store"
)

const testDBFilename = "./testStore.db"

func cleanup() {
	_ = os.Remove(testDBFilename)
}

func TestRefreshToken(t *testing.T) {
	t.Cleanup(cleanup)

	manager := initManager()
	if manager == nil {
		t.Fatal("failed to initialize token manager\n")
	}
	defer manager.Close()

	const testUserID = "abcd"
	const testUserEmail = "user@test.com"
	refreshToken, err := manager.NewRefreshToken(testUserID, testUserEmail)
	if err != nil {
		t.Fatalf("failed to create refresh token: %s\n", err)
	}

	user, err := manager.VerifyRefreshToken(refreshToken.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Error("got nil user from refresh token\n")
	}
	if user.GetID() != testUserID {
		t.Errorf("wrong user ID in refresh token, want %s got %s\n", testUserID, user.GetID())
	}
}

func TestInvalidRefreshToken(t *testing.T) {
	t.Cleanup(cleanup)

	manager := initManager()
	if manager == nil {
		t.Fatal("failed to initialize token manager\n")
	}
	defer manager.Close()

	user, err := manager.VerifyRefreshToken("this is not a valid token ID")
	if !errors.Is(token.ErrTokenInvalid, err) {
		t.Errorf("expected %s got %s\n", token.ErrTokenInvalid, err)
	}
	if user != nil {
		t.Errorf("invalid user object should be nil, got %s\n", user)
	}
}

func TestAccessToken(t *testing.T) {
	t.Cleanup(cleanup)

	manager := initManager()
	if manager == nil {
		t.Fatal("failed to initialize token manager\n")
	}
	defer manager.Close()

	const testUserID = "efgh"
	const testUserEmail = "someone@test.com"
	refreshToken, err := manager.NewRefreshToken(testUserID, testUserEmail)
	if err != nil {
		t.Fatalf("failed to create refresh token: %s\n", err)
	}

	accessToken, _, err := manager.NewAccessToken(refreshToken.TokenID)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := manager.VerifyAccessToken(accessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != testUserID {
		t.Errorf("wrong user ID in access token, want %s got %s\n", testUserID, claims.UserID)
	}
	if claims.Email != testUserEmail {
		t.Errorf("wrong email in access token, want %s got %s\n", testUserEmail, claims.Email)
	}
}

func TestInvalidAccessToken(t *testing.T) {
	t.Cleanup(cleanup)

	manager := initManager()
	if manager == nil {
		t.Fatal("failed to initialize token manager\n")
	}
	defer manager.Close()

	const (
		dumbAccessToken = "this is not a valid access token string"
		// This is a real signed ED25519 JWT but signed with a random key
		invalidSignatureToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JkKWCY39IdWEQttmdqR7VdsvT-_QxheW_eb0S5wr_j83ltux_JDUIXs7a3Dtn3xuqzuhetiuJrWIvy5TzimeCg"
	)

	claims, err := manager.VerifyAccessToken(dumbAccessToken)
	if !errors.Is(err, token.ErrTokenMalformed) {
		t.Errorf("wrong error want %s got %s", token.ErrTokenMalformed, err)
	}

	if claims != nil {
		t.Errorf("invalid claims object should be nil, got %s\n", claims)
	}

	claims, err = manager.VerifyAccessToken(invalidSignatureToken)
	if !errors.Is(err, token.ErrTokenInvalid) {
		t.Errorf("wrong error want %s got %s", token.ErrTokenInvalid, err)
	}

	if claims != nil {
		t.Errorf("invalid claims object should be nil, got %s\n", claims)
	}
}

func initManager() *token.Manager {
	s, err := store.InitSQLiteStore(testDBFilename)
	if err != nil {
		return nil
	}
	_, privKey, _ := ed25519.GenerateKey(nil)

	return token.NewManager(s, privKey)
}
