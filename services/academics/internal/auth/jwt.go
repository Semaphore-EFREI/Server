package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID    string  `json:"user_id"`
	UserType  string  `json:"user_type"`
	SchoolID  string  `json:"school_id"`
	AdminRole *string `json:"admin_role,omitempty"`
	jwt.RegisteredClaims
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
