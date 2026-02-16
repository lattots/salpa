package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/models"
)

type Store interface {
	Add(ctx context.Context, token models.RefreshToken, email string) error

	Check(ctx context.Context, tokenID string) (bool, models.User, error)
	Remove(ctx context.Context, tokenID string) error

	RemoveAllForUser(ctx context.Context, userID string) error

	Close() error
}

func CreateStore(conf config.StoreConfig) (Store, error) {
	var store Store
	var err error
	switch conf.Driver {
	case "sqlite":
		db, err := sql.Open("sqlite3", conf.ConnectionString)
		if err != nil {
			return nil, err
		}
		store, err = NewSQLiteStore(db)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown store driver: %s", conf.Driver)
	}

	return store, err
}

type storeUser struct {
	id    string
	email string
}

func (u storeUser) GetID() string {
	return u.id
}

func (u storeUser) GetEmail() string {
	return u.email
}
