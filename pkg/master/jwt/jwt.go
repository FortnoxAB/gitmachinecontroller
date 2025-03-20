package jwt

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

	AllowedIP string `json:"allowedIp"`
	// Admin is allowed to do apply and exec commands
	Admin bool `json:"admin"`
	jwt.RegisteredClaims
}

func (j *JWTHandler) ValidateToken(signedToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
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

	return claims, nil
}

func (j *JWTHandler) GenerateJWT(claims *Claims) (tokenString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(j.key)
	return
}

func (j *JWTHandler) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Request.Header.Get("Authorization")
		claims, err := j.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		if !claims.Admin {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Next()
	}
}

func DefaultClaims(opts ...OptionsFunc) *Claims {
	expirationTime := time.Now().Add(24 * time.Hour)
	claim := &Claims{
		Allowed: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
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
func OptionAllowedIP(ip string) OptionsFunc {
	return func(claim *Claims) {
		claim.AllowedIP = ip
	}
}
func OptionAdmin() OptionsFunc {
	return func(claim *Claims) {
		claim.Admin = true
	}
}
