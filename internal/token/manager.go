package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lattots/salpa/internal/config"
	"github.com/lattots/salpa/internal/models"
	"github.com/lattots/salpa/internal/token/store"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
)

type Manager struct {
	accessTokenPrivate ed25519.PrivateKey
	AccessTokenPublic  ed25519.PublicKey

	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration

	refreshTokenStore store.Store
}

const (
	defaultAccessTokenTTL  = time.Minute * 10
	defaultRefreshTokenTTL = time.Hour * 24 * 30 // Refresh tokens are valid for a month
)

func NewManager(store store.Store, acPriv ed25519.PrivateKey) *Manager {
	return &Manager{
		accessTokenPrivate: acPriv,
		AccessTokenPublic:  acPriv.Public().(ed25519.PublicKey),
		accessTokenTTL:     defaultAccessTokenTTL,

		refreshTokenTTL: defaultRefreshTokenTTL,

		refreshTokenStore: store,
	}
}

func NewManagerFromConf(conf config.SystemConfiguration, store store.Store) (*Manager, error) {
	privateKey, err := loadPrivateKey(conf.Service.PrivateKeyFilename)
	if err != nil {
		return nil, err
	}

	manager := NewManager(store, privateKey)
	return manager, nil
}

func (m *Manager) Close() error {
	return m.refreshTokenStore.Close()
}

func (m *Manager) verifyToken(tokenStr string, keyFunc func(token *jwt.Token) (any, error)) (*models.UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &models.UserClaims{}, keyFunc)
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return nil, ErrTokenInvalid
	}
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return nil, ErrTokenMalformed
	}
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}
	if !token.Valid {
		return nil, ErrTokenInvalid
	}
	claims := token.Claims.(*models.UserClaims)
	return claims, nil
}

func (m *Manager) getAccessPublic(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
		return nil, errors.New("unexpected signing method")
	}
	return m.AccessTokenPublic, nil
}

func loadPrivateKey(filename string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		err = generateED25519Key(filename)
		if err != nil {
			return nil, err
		}
	}
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	parsedKey, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenSSH key: %w", err)
	}

	ed25519Key, ok := parsedKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not of type ed25519.PrivateKey, got: %T", parsedKey)
	}

	return *ed25519Key, nil
}

// generateED25519Key creates a new ED25519 private key and saves it to a file
func generateED25519Key(filename string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	privBytes := pem.EncodeToMemory(privBlock)

	err = os.WriteFile(filename, privBytes, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}
