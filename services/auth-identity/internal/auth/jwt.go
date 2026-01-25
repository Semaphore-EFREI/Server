package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID    string  `json:"user_id"`
	UserType  string  `json:"user_type"`
	SchoolID  string  `json:"school_id"`
	AdminRole *string `json:"admin_role,omitempty"`
	jwt.RegisteredClaims
}

func NewAccessToken(secret, issuer string, ttl time.Duration, claims Claims) (string, error) {
	now := time.Now().UTC()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   claims.UserID,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ParseToken(secret, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}
