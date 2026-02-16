package token

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenInvalid   = errors.New("Token invalid")
	ErrTokenMalformed = jwt.ErrTokenMalformed
)
