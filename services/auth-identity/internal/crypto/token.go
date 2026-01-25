package crypto

import (
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
)

func NewRefreshToken() (string, error) {
  buf := make([]byte, 32)
  if _, err := rand.Read(buf); err != nil {
    return "", err
  }
  return base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashToken(token string) string {
  sum := sha256.Sum256([]byte(token))
  return base64.RawURLEncoding.EncodeToString(sum[:])
}
