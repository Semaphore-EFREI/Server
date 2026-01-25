package auth

import (
  "testing"
  "time"
)

func TestAccessTokenRoundTrip(t *testing.T) {
  token, err := NewAccessToken("secret", "issuer", time.Minute, Claims{
    UserID:   "user-1",
    UserType: "student",
    SchoolID: "school-1",
  })
  if err != nil {
    t.Fatalf("token error: %v", err)
  }

  claims, err := ParseToken("secret", token)
  if err != nil {
    t.Fatalf("parse error: %v", err)
  }

  if claims.UserID != "user-1" || claims.UserType != "student" || claims.SchoolID != "school-1" {
    t.Fatalf("unexpected claims")
  }
}
