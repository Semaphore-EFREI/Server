package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

func NewAccessToken(privateKey *rsa.PrivateKey, issuer string, ttl time.Duration, claims Claims) (string, error) {
	if privateKey == nil {
		return "", errors.New("missing_private_key")
	}
	now := time.Now().UTC()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   claims.UserID,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid, err := KeyID(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid
	return token.SignedString(privateKey)
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

func ParseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid_private_key")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid_private_key_type")
	}
	return privateKey, nil
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

func KeyID(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
