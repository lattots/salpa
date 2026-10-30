package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lattots/salpa/internal/models"
)

type managerTestUser struct{ id, email string }

func (u managerTestUser) GetID() string    { return u.id }
func (u managerTestUser) GetEmail() string { return u.email }

type managerTestStore struct{ sessions map[string]managerTestUser }

func newManagerTestStore() *managerTestStore {
	return &managerTestStore{sessions: make(map[string]managerTestUser)}
}
func (s *managerTestStore) Add(_ context.Context, t models.RefreshToken, email string) error {
	s.sessions[t.TokenID] = managerTestUser{id: t.UserID, email: email}
	return nil
}
func (s *managerTestStore) Check(_ context.Context, id string) (bool, models.User, error) {
	u, ok := s.sessions[id]
	if !ok {
		return false, nil, nil
	}
	return true, u, nil
}
func (s *managerTestStore) Remove(_ context.Context, id string) error {
	delete(s.sessions, id)
	return nil
}
func (s *managerTestStore) RemoveAllForUser(_ context.Context, id string) error {
	for tokenID, user := range s.sessions {
		if user.GetID() == id {
			delete(s.sessions, tokenID)
		}
	}
	return nil
}
func (s *managerTestStore) Close() error { return nil }

func newManagerForTest(t *testing.T) (*Manager, *managerTestStore) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := newManagerTestStore()
	return NewManager(s, privateKey), s
}

func TestAccessTokenRoundTrip(t *testing.T) {
	m, _ := newManagerForTest(t)
	refresh, err := m.NewRefreshToken("user-42", "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	access, expiresAt, err := m.NewAccessToken(refresh.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.VerifyAccessToken(access)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.UserID != "user-42" || claims.Email != "user@example.test" || claims.Subject != "user-42" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if !expiresAt.After(time.Now()) {
		t.Fatalf("access token expiry is not in the future: %v", expiresAt)
	}
}

func TestRevokedRefreshTokenCannotMintAccessToken(t *testing.T) {
	m, s := newManagerForTest(t)
	refresh, err := m.NewRefreshToken("user-42", "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(context.Background(), refresh.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.NewAccessToken(refresh.TokenID); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("NewAccessToken after revocation error = %v, want ErrTokenInvalid", err)
	}
}

func TestExpiredAccessTokenIsClassifiedAsInvalid(t *testing.T) {
	m, _ := newManagerForTest(t)
	claims := models.NewUserClaims("user-1", "user@example.test", -time.Minute)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := jwtToken.SignedString(m.accessTokenPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyAccessToken(signed); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token error = %v, want ErrTokenInvalid", err)
	}
}

func TestAccessTokenRejectsWrongSigningAlgorithm(t *testing.T) {
	m, _ := newManagerForTest(t)
	claims := models.NewUserClaims("user-1", "user@example.test", time.Minute)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := jwtToken.SignedString([]byte("not-the-ed25519-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyAccessToken(signed); err == nil {
		t.Fatal("accepted an HMAC-signed token")
	}
}

func TestMalformedAccessTokenHasStableError(t *testing.T) {
	m, _ := newManagerForTest(t)
	if _, err := m.VerifyAccessToken("not.a.jwt"); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("error = %v, want ErrTokenMalformed", err)
	}
}

func TestLoadPrivateKeyCreatesStablePrivateKeyFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "private_key")
	first, err := loadPrivateKey(filename)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("private key permissions = %o, want no group/other permissions", info.Mode().Perm())
	}
	second, err := loadPrivateKey(filename)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("loading the same key file produced a different private key")
	}
}

func TestLoadPrivateKeyRejectsMalformedFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "bad_key")
	if err := os.WriteFile(filename, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrivateKey(filename); err == nil {
		t.Fatal("accepted malformed private key file")
	}
}
