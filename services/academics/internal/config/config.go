package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr               string
	GRPCAddr               string
	DatabaseURL            string
	JWTSecret              string
	JWTIssuer              string
	CourseDuration         time.Duration
	CourseDefaultRangeDays int
}

func Load() Config {
	return Config{
		HTTPAddr:               getenv("HTTP_ADDR", ":8082"),
		GRPCAddr:               getenv("GRPC_ADDR", ":9092"),
		DatabaseURL:            getenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/academics?sslmode=disable"),
		JWTSecret:              getenv("JWT_SECRET", "dev-secret"),
		JWTIssuer:              getenv("JWT_ISSUER", "semaphore-auth-identity"),
		CourseDuration:         getenvDuration("COURSE_DURATION", time.Hour),
		CourseDefaultRangeDays: getenvInt("COURSE_DEFAULT_RANGE_DAYS", 10),
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

func getenvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return fallback
}
