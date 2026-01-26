package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestAccessTokenRoundTrip(t *testing.T) {
	privateKey := mustPrivateKey(t)
	publicKey := &privateKey.PublicKey

	token, err := NewAccessToken(privateKey, "issuer", time.Minute, Claims{
		UserID:   "user-1",
		UserType: "student",
		SchoolID: "school-1",
	})
	if err != nil {
		t.Fatalf("token error: %v", err)
	}

	claims, err := ParseToken(publicKey, "issuer", token)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if claims.UserID != "user-1" || claims.UserType != "student" || claims.SchoolID != "school-1" {
		t.Fatalf("unexpected claims")
	}
}

func mustPrivateKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen error: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	parsed, err := ParseRSAPrivateKey(string(pemData))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return parsed
}
