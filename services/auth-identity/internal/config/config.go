package config

import (
  "os"
  "strconv"
  "time"
)

type Config struct {
  HTTPAddr          string
  DatabaseURL       string
  JWTSecret         string
  JWTIssuer         string
  AccessTokenTTL    time.Duration
  RefreshTokenTTL   time.Duration
  DeviceRebindAfter time.Duration
}

func Load() Config {
  return Config{
    HTTPAddr:          getenv("HTTP_ADDR", ":8081"),
    DatabaseURL:       getenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/auth_identity?sslmode=disable"),
    JWTSecret:         getenv("JWT_SECRET", "dev-secret"),
    JWTIssuer:         getenv("JWT_ISSUER", "semaphore-auth-identity"),
    AccessTokenTTL:    getenvDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
    RefreshTokenTTL:   getenvDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
    DeviceRebindAfter: getenvDuration("DEVICE_REBIND_AFTER", 7*24*time.Hour),
  }
}

func getenv(key, fallback string) string {
  if val := os.Getenv(key); val != "" {
    return val
  }
  return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
  if val := os.Getenv(key); val != "" {
    if parsed, err := time.ParseDuration(val); err == nil {
      return parsed
    }
  }
  if val := os.Getenv(key + "_SECONDS"); val != "" {
    if seconds, err := strconv.Atoi(val); err == nil {
      return time.Duration(seconds) * time.Second
    }
  }
  return fallback
}
