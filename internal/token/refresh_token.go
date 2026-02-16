package token

import (
	"context"
	"fmt"
	"time"

	"github.com/lattots/salpa/internal/models"

	"github.com/google/uuid"
)

func (m *Manager) NewRefreshToken(userID, email string) (models.RefreshToken, error) {
	token := models.RefreshToken{
		TokenID:   uuid.New().String(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(m.refreshTokenTTL),
	}
	err := m.refreshTokenStore.Add(context.TODO(), token, email)
	if err != nil {
		return models.RefreshToken{}, err
	}
	return token, nil
}

func (m *Manager) VerifyRefreshToken(tokenID string) (models.User, error) {
	valid, user, err := m.refreshTokenStore.Check(context.TODO(), tokenID)
	if err != nil {
		return nil, fmt.Errorf("error checking refresh token: %w", err)
	}
	if !valid {
		return nil, ErrTokenInvalid
	}

	return user, nil
}
