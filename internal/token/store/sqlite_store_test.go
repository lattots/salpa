package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/token/store"
)

const testDBFilename = "./testStore.db"

func cleanup() {
	_ = os.Remove(testDBFilename)
}

func TestSQLiteStore_AddAndCheck(t *testing.T) {
	t.Cleanup(cleanup)

	store, err := store.InitSQLiteStore(testDBFilename)
	if err != nil {
		t.Fatalf("error initializing store: %s\n", err)
	}
	ctx := context.Background()

	token := models.RefreshToken{
		TokenID:   "token_123",
		UserID:    "user_abc",
		ExpiresAt: time.Now().Add(1 * time.Hour), // Expires in future
	}
	email := "test@example.com"

	err = store.Add(ctx, token, email)
	if err != nil {
		t.Fatalf("Add() failed: %v", err)
	}

	exists, user, err := store.Check(ctx, token.TokenID)
	if err != nil {
		t.Fatalf("Check() returned error: %v", err)
	}
	if !exists {
		t.Error("Check() returned false, expected true for valid token")
	}

	if user == nil {
		t.Error("expected user object, got nil")
	}
}

func TestSQLiteStore_Check_Expired(t *testing.T) {
	t.Cleanup(cleanup)

	store, err := store.InitSQLiteStore(testDBFilename)
	if err != nil {
		t.Fatalf("error initializing store: %s\n", err)
	}
	ctx := context.Background()

	token := models.RefreshToken{
		TokenID:   "expired_token",
		UserID:    "user_abc",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Token is set to expire an hour ago
	}

	err = store.Add(ctx, token, "test@example.com")
	if err != nil {
		t.Fatalf("setup insert failed: %v", err)
	}

	exists, _, err := store.Check(ctx, token.TokenID)
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}
	if exists {
		t.Error("Check() returned true, expected false for expired token")
	}
}

func TestSQLiteStore_Remove(t *testing.T) {
	t.Cleanup(cleanup)

	store, err := store.InitSQLiteStore(testDBFilename)
	if err != nil {
		t.Fatalf("error initializing store: %s\n", err)
	}
	ctx := context.Background()

	token := models.RefreshToken{
		TokenID:   "token_to_remove",
		UserID:    "user_1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	store.Add(ctx, token, "email@test.com")

	err = store.Remove(ctx, token.TokenID)
	if err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}

	exists, _, _ := store.Check(ctx, token.TokenID)
	if exists {
		t.Error("token still exists after Remove()")
	}
}

func TestSQLiteStore_RemoveAllForUser(t *testing.T) {
	t.Cleanup(cleanup)

	store, err := store.InitSQLiteStore(testDBFilename)
	if err != nil {
		t.Fatalf("error initializing store: %s\n", err)
	}
	ctx := context.Background()

	userA := "user_A"
	userB := "user_B"

	store.Add(ctx, models.RefreshToken{TokenID: "t1", UserID: userA, ExpiresAt: time.Now().Add(time.Hour)}, "a@test.com")
	store.Add(ctx, models.RefreshToken{TokenID: "t2", UserID: userA, ExpiresAt: time.Now().Add(time.Hour)}, "a@test.com")
	store.Add(ctx, models.RefreshToken{TokenID: "t3", UserID: userB, ExpiresAt: time.Now().Add(time.Hour)}, "b@test.com")

	err = store.RemoveAllForUser(ctx, userA)
	if err != nil {
		t.Fatalf("RemoveAllForUser() failed: %v", err)
	}

	if exists, _, _ := store.Check(ctx, "t1"); exists {
		t.Error("t1 (User A) should have been deleted")
	}
	if exists, _, _ := store.Check(ctx, "t2"); exists {
		t.Error("t2 (User A) should have been deleted")
	}
	// User B token should remain
	if exists, _, _ := store.Check(ctx, "t3"); !exists {
		t.Error("t3 (User B) should NOT have been deleted")
	}
}
