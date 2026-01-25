package crypto

import "testing"

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	if err := CheckPassword(hash, "secret"); err != nil {
		t.Fatalf("expected password to match")
	}
	if err := CheckPassword(hash, "wrong"); err == nil {
		t.Fatalf("expected password mismatch")
	}
}
