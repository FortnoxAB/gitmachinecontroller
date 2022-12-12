package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type JWTHandler struct {
	key []byte
}

func New(key string) *JWTHandler {
	return &JWTHandler{
		key: []byte(key),
	}
}

type Claim struct {
	Host    string `json:"host"`
	Allowed bool   `json:"allowed"`
	jwt.StandardClaims
}

func (j *JWTHandler) ValidateToken(signedToken string) (*Claim, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&Claim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(j.key), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("auth: error validating: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token not valid")
	}

	claims, ok := token.Claims.(*Claim)
	if !ok {
		return nil, fmt.Errorf("couldn't parse claims: ")
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

func (j *JWTHandler) GenerateJWT(hostname string) (tokenString string, err error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claim{
		Host:    hostname,
		Allowed: true,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(j.key)
	return
}
