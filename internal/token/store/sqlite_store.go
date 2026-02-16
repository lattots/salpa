package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lattots/salpa/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

type sqLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(db *sql.DB) (Store, error) {
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &sqLiteStore{db: db}, nil
}

func InitSQLiteStore(filename string) (Store, error) {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			userID TEXT NOT NULL,
			email text NOT NULL,
			expiresAt INTEGER NOT NULL
		);
	`)
	if err != nil {
		return nil, err
	}

	return NewSQLiteStore(db)
}

// Add inserts a new session record.
func (s *sqLiteStore) Add(ctx context.Context, token models.RefreshToken, email string) error {
	query := `INSERT INTO sessions (id, userID, email, expiresAt) VALUES (?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query, token.TokenID, token.UserID, email, token.ExpiresAt.Unix())
	return err
}

// Check returns true if the token exists AND is not expired.
func (s *sqLiteStore) Check(ctx context.Context, tokenID string) (bool, models.User, error) {
	query := `SELECT userID, email FROM sessions WHERE id = ? AND expiresAt > ?`

	user := storeUser{}
	err := s.db.QueryRowContext(ctx, query, tokenID, time.Now().Unix()).Scan(&user.id, &user.email)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}

	return true, user, nil
}

// Remove deletes a specific session (used for logout).
func (s *sqLiteStore) Remove(ctx context.Context, tokenID string) error {
	query := `DELETE FROM sessions WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, tokenID)
	return err
}

// RemoveAllForUser deletes all sessions for a user (security reset).
func (s *sqLiteStore) RemoveAllForUser(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE userID = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}

func (s *sqLiteStore) Close() error {
	return s.db.Close()
}
