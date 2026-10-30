package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/token/store"
)

func TestCreateStoreInitializesSQLiteSchema(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "sessions.sqlite")
	s, err := store.CreateStore(config.StoreConfig{
		Driver:           "sqlite",
		ConnectionString: filename,
	})
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	defer s.Close()

	refresh := models.RefreshToken{
		TokenID:   "refresh-1",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.Add(context.Background(), refresh, "user@example.test"); err != nil {
		t.Fatalf("Add after CreateStore: %v (sessions table may not have been initialized)", err)
	}
	valid, user, err := s.Check(context.Background(), refresh.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if !valid || user.GetID() != refresh.UserID || user.GetEmail() != "user@example.test" {
		t.Fatalf("Check = (%v, %#v), want valid user %q", valid, user, refresh.UserID)
	}
}

func TestSQLiteStoreSessionLifecycle(t *testing.T) {
	s, err := store.InitSQLiteStore(filepath.Join(t.TempDir(), "sessions.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	valid := models.RefreshToken{TokenID: "valid", UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)}
	expired := models.RefreshToken{TokenID: "expired", UserID: "user-1", ExpiresAt: time.Now().Add(-time.Minute)}
	other := models.RefreshToken{TokenID: "other-user", UserID: "user-2", ExpiresAt: time.Now().Add(time.Hour)}
	for _, item := range []struct {
		token models.RefreshToken
		email string
	}{{valid, "one@example.test"}, {expired, "one@example.test"}, {other, "two@example.test"}} {
		if err := s.Add(ctx, item.token, item.email); err != nil {
			t.Fatalf("Add(%q): %v", item.token.TokenID, err)
		}
	}

	ok, user, err := s.Check(ctx, valid.TokenID)
	if err != nil || !ok || user.GetID() != "user-1" || user.GetEmail() != "one@example.test" {
		t.Fatalf("valid Check = (%v, %#v, %v)", ok, user, err)
	}
	ok, _, err = s.Check(ctx, expired.TokenID)
	if err != nil || ok {
		t.Fatalf("expired Check = (%v, %v), want false, nil", ok, err)
	}
	ok, _, err = s.Check(ctx, "missing")
	if err != nil || ok {
		t.Fatalf("missing Check = (%v, %v), want false, nil", ok, err)
	}

	if err := s.Remove(ctx, valid.TokenID); err != nil {
		t.Fatal(err)
	}
	ok, _, err = s.Check(ctx, valid.TokenID)
	if err != nil || ok {
		t.Fatalf("Check after Remove = (%v, %v), want false, nil", ok, err)
	}

	if err := s.RemoveAllForUser(ctx, "user-1"); err != nil {
		t.Fatal(err)
	}
	ok, _, err = s.Check(ctx, "other-user")
	if err != nil || !ok {
		t.Fatalf("RemoveAllForUser removed another user's session: (%v, %v)", ok, err)
	}
}

func TestCreateStoreRejectsUnknownDriver(t *testing.T) {
	if _, err := store.CreateStore(config.StoreConfig{Driver: "not-a-driver"}); err == nil {
		t.Fatal("CreateStore accepted an unknown driver")
	}
}
