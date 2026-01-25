package config

import (
	"testing"
	"time"
)

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("HTTP_ADDR", ":18081")
	t.Setenv("GRPC_ADDR", ":19091")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/testdb")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("JWT_ISSUER", "test-issuer")
	t.Setenv("ACCESS_TOKEN_TTL", "30m")
	t.Setenv("REFRESH_TOKEN_TTL", "48h")
	t.Setenv("DEVICE_REBIND_AFTER_SECONDS", "3600")

	cfg := Load()
	if cfg.HTTPAddr != ":18081" {
		t.Fatalf("expected HTTP_ADDR override, got %s", cfg.HTTPAddr)
	}
	if cfg.GRPCAddr != ":19091" {
		t.Fatalf("expected GRPC_ADDR override, got %s", cfg.GRPCAddr)
	}
	if cfg.DatabaseURL != "postgres://user:pass@localhost:5432/testdb" {
		t.Fatalf("expected DATABASE_URL override, got %s", cfg.DatabaseURL)
	}
	if cfg.JWTSecret != "test-secret" {
		t.Fatalf("expected JWT_SECRET override, got %s", cfg.JWTSecret)
	}
	if cfg.JWTIssuer != "test-issuer" {
		t.Fatalf("expected JWT_ISSUER override, got %s", cfg.JWTIssuer)
	}
	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Fatalf("expected ACCESS_TOKEN_TTL 30m, got %s", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 48*time.Hour {
		t.Fatalf("expected REFRESH_TOKEN_TTL 48h, got %s", cfg.RefreshTokenTTL)
	}
	if cfg.DeviceRebindAfter != time.Hour {
		t.Fatalf("expected DEVICE_REBIND_AFTER 1h, got %s", cfg.DeviceRebindAfter)
	}
}
