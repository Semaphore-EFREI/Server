package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr          string
	GRPCAddr          string
	DatabaseURL       string
	JWTSecret         string
	JWTIssuer         string
	AcademicsGRPCAddr string
	IdentityGRPCAddr  string
	GRPCDialTimeout   time.Duration
}

func Load() Config {
	return Config{
		HTTPAddr:          getenv("HTTP_ADDR", ":8083"),
		GRPCAddr:          getenv("GRPC_ADDR", ":9093"),
		DatabaseURL:       getenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/attendance?sslmode=disable"),
		JWTSecret:         getenv("JWT_SECRET", "dev-secret"),
		JWTIssuer:         getenv("JWT_ISSUER", "semaphore-auth-identity"),
		AcademicsGRPCAddr: getenv("ACADEMICS_GRPC_ADDR", "127.0.0.1:9092"),
		IdentityGRPCAddr:  getenv("IDENTITY_GRPC_ADDR", "127.0.0.1:9091"),
		GRPCDialTimeout:   getenvDuration("GRPC_DIAL_TIMEOUT", 5*time.Second),
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
