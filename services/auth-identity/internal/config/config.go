package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr           string
	GRPCAddr           string
	DatabaseURL        string
	JWTPrivateKey      string
	JWTPublicKey       string
	JWTIssuer          string
	ServiceAuthToken   string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	DeviceRebindAfter  time.Duration
	AcademicsGRPCAddr  string
	AttendanceGRPCAddr string
	GRPCDialTimeout    time.Duration
}

func Load() Config {
	return Config{
		HTTPAddr:           getenv("HTTP_ADDR", ":8081"),
		GRPCAddr:           getenv("GRPC_ADDR", ":9091"),
		DatabaseURL:        getenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/auth_identity?sslmode=disable"),
		JWTPrivateKey:      getenvKey("JWT_PRIVATE_KEY", ""),
		JWTPublicKey:       getenvKey("JWT_PUBLIC_KEY", ""),
		JWTIssuer:          getenv("JWT_ISSUER", "semaphore-auth-identity"),
		ServiceAuthToken:   getenv("SERVICE_AUTH_TOKEN", ""),
		AccessTokenTTL:     getenvDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:    getenvDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		DeviceRebindAfter:  getenvDuration("DEVICE_REBIND_AFTER", 7*24*time.Hour),
		AcademicsGRPCAddr:  getenv("ACADEMICS_GRPC_ADDR", "127.0.0.1:9092"),
		AttendanceGRPCAddr: getenv("ATTENDANCE_GRPC_ADDR", "127.0.0.1:9093"),
		GRPCDialTimeout:    getenvDuration("GRPC_DIAL_TIMEOUT", 5*time.Second),
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

func getenvKey(key, fallback string) string {
	if file := os.Getenv(key + "_FILE"); file != "" {
		if data, err := os.ReadFile(file); err == nil {
			return normalizePEM(string(data))
		}
	}
	if val := os.Getenv(key); val != "" {
		return normalizePEM(val)
	}
	return fallback
}

func normalizePEM(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "\\n") && !strings.Contains(value, "\n") {
		value = strings.ReplaceAll(value, "\\n", "\n")
	}
	return value
}
