package models

import "time"

type RefreshToken struct {
	UserID    string
	TokenID   string
	ExpiresAt time.Time
}
