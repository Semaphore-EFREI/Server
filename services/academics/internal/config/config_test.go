package config

import (
	"testing"
	"time"
)

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("HTTP_ADDR", ":18082")
	t.Setenv("GRPC_ADDR", ":19092")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/academics_test")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("JWT_ISSUER", "test-issuer")
	t.Setenv("COURSE_DURATION", "90m")
	t.Setenv("COURSE_DEFAULT_RANGE_DAYS", "5")

	cfg := Load()
	if cfg.HTTPAddr != ":18082" {
		t.Fatalf("expected HTTP_ADDR override, got %s", cfg.HTTPAddr)
	}
	if cfg.GRPCAddr != ":19092" {
		t.Fatalf("expected GRPC_ADDR override, got %s", cfg.GRPCAddr)
	}
	if cfg.DatabaseURL != "postgres://user:pass@localhost:5432/academics_test" {
		t.Fatalf("expected DATABASE_URL override, got %s", cfg.DatabaseURL)
	}
	if cfg.JWTSecret != "test-secret" {
		t.Fatalf("expected JWT_SECRET override, got %s", cfg.JWTSecret)
	}
	if cfg.JWTIssuer != "test-issuer" {
		t.Fatalf("expected JWT_ISSUER override, got %s", cfg.JWTIssuer)
	}
	if cfg.CourseDuration != 90*time.Minute {
		t.Fatalf("expected COURSE_DURATION 90m, got %s", cfg.CourseDuration)
	}
	if cfg.CourseDefaultRangeDays != 5 {
		t.Fatalf("expected COURSE_DEFAULT_RANGE_DAYS 5, got %d", cfg.CourseDefaultRangeDays)
	}
}
