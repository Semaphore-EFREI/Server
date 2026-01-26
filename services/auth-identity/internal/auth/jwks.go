package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
)

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewJWKSet(publicKey *rsa.PublicKey) (JWKSet, error) {
	if publicKey == nil {
		return JWKSet{}, errors.New("missing_public_key")
	}
	kid, err := KeyID(publicKey)
	if err != nil {
		return JWKSet{}, err
	}
	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(intToBytes(publicKey.E)),
	}
	return JWKSet{Keys: []JWK{jwk}}, nil
}

func intToBytes(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	return big.NewInt(int64(value)).Bytes()
}
