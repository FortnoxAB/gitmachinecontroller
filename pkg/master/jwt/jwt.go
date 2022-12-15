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

type Claims struct {
	// Host is the hostname of an agent
	Host string `json:"host"`
	// Allowed controls if agent is allowd to get git config from master
	Allowed bool `json:"allowed"`
	// Admin is allowed to do apply and exec commands
	Admin bool `json:"admin"`
	jwt.StandardClaims
}

func (j *JWTHandler) ValidateToken(signedToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&Claims{},
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

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("couldn't parse claims: ")
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

func (j *JWTHandler) GenerateJWT(claims *Claims) (tokenString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(j.key)
	return
}

func DefaultClaims(opts ...OptionsFunc) *Claims {
	expirationTime := time.Now().Add(24 * time.Hour)
	claim := &Claims{
		Allowed: true,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	for _, o := range opts {
		o(claim)
	}
	return claim
}

type OptionsFunc func(*Claims)

func OptionHostname(name string) OptionsFunc {
	return func(claim *Claims) {
		claim.Host = name
	}
}
func OptionAdmin() OptionsFunc {
	return func(claim *Claims) {
		claim.Admin = true
	}
}
