package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID    string  `json:"user_id"`
	UserType  string  `json:"user_type"`
	SchoolID  string  `json:"school_id"`
	AdminRole *string `json:"admin_role,omitempty"`
	jwt.RegisteredClaims
}

func ParseToken(publicKey *rsa.PublicKey, issuer, tokenString string) (*Claims, error) {
	if publicKey == nil {
		return nil, errors.New("missing_public_key")
	}
	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
	}
	if issuer != "" {
		options = append(options, jwt.WithIssuer(issuer))
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, options...)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func ParseRSAPublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid_public_key")
	}
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid_public_key_type")
		}
		return publicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, errors.New("invalid_public_key")
	}
}
