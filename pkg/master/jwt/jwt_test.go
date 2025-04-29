package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestValidateToken(t *testing.T) {

	h := &JWTHandler{key: []byte("asdfasdf")}

	cl := &Claims{
		Host:  "test",
		Admin: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}
	jwtStr, err := h.GenerateJWT(cl)
	assert.NoError(t, err)

	validatedClaims, err := h.ValidateToken(jwtStr)
	assert.NoError(t, err)

	assert.Equal(t, "test", validatedClaims.Host)
	assert.Equal(t, true, validatedClaims.Admin)
}

func TestValidateTokenExpired(t *testing.T) {

	h := &JWTHandler{key: []byte("asdfasdf")}

	cl := &Claims{
		Host:  "test",
		Admin: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * -1)), // one hour in the past
		},
	}
	jwtStr, err := h.GenerateJWT(cl)
	assert.NoError(t, err)

	_, err = h.ValidateToken(jwtStr)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)

}
