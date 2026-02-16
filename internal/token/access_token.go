package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lattots/salpa/internal/models"
)

func (m *Manager) NewAccessToken(refreshToken string) (string, time.Time, error) {
	user, err := m.VerifyRefreshToken(refreshToken)
	if err != nil {
		return "", time.Time{}, err
	}

	newClaims := models.NewUserClaims(user.GetID(), user.GetEmail(), m.accessTokenTTL)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, newClaims)
	signed, err := token.SignedString(m.accessTokenPrivate)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error signing token: %w", err)
	}
	return signed, newClaims.ExpiresAt.Time, nil
}

func (m *Manager) VerifyAccessToken(accessTokenString string) (*models.UserClaims, error) {
	return m.verifyToken(accessTokenString, m.getAccessPublic)
}
