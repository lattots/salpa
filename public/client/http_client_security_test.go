package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lattots/salpa/internal/models"
)

func newHTTPClientForTest(t *testing.T) (*httpClient, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &httpClient{verificationKey: publicKey}, privateKey
}

func TestVerifyTokenAcceptsValidEdDSAToken(t *testing.T) {
	c, privateKey := newHTTPClientForTest(t)
	claims := models.NewUserClaims("user-1", "user@example.test", time.Minute)
	encoded, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.VerifyToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "user-1" {
		t.Fatalf("UserID = %q, want user-1", got.UserID)
	}
}

func TestVerifyTokenNormalizesExpiredTokenToErrInvalidToken(t *testing.T) {
	c, privateKey := newHTTPClientForTest(t)
	claims := models.NewUserClaims("user-1", "user@example.test", -time.Minute)
	encoded, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyToken(encoded); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyToken error = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyTokenRejectsWrongSigningAlgorithm(t *testing.T) {
	c, _ := newHTTPClientForTest(t)
	claims := models.NewUserClaims("user-1", "user@example.test", time.Minute)
	encoded, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("attacker-controlled-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyToken(encoded); err == nil {
		t.Fatal("accepted HMAC token")
	}
}
