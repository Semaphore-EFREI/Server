package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr               string
	GRPCAddr               string
	DatabaseURL            string
	JWTPublicKey           string
	JWTIssuer              string
	BeaconHTTPAddr         string
	AttendanceGRPCAddr     string
	BeaconGRPCAddr         string
	GRPCDialTimeout        time.Duration
	CourseDuration         time.Duration
	CourseDefaultRangeDays int
}

func Load() Config {
	return Config{
		HTTPAddr:               getenv("HTTP_ADDR", ":8082"),
		GRPCAddr:               getenv("GRPC_ADDR", ":9092"),
		DatabaseURL:            getenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/academics?sslmode=disable"),
		JWTPublicKey:           getenvKey("JWT_PUBLIC_KEY", ""),
		JWTIssuer:              getenv("JWT_ISSUER", "semaphore-auth-identity"),
		BeaconHTTPAddr:         getenv("BEACON_HTTP_ADDR", "http://beacon:8084"),
		AttendanceGRPCAddr:     getenv("ATTENDANCE_GRPC_ADDR", "127.0.0.1:9093"),
		BeaconGRPCAddr:         getenv("BEACON_GRPC_ADDR", "127.0.0.1:9094"),
		GRPCDialTimeout:        getenvDuration("GRPC_DIAL_TIMEOUT", 5*time.Second),
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
