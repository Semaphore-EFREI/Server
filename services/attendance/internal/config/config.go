package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr                  string
	GRPCAddr                  string
	DatabaseURL               string
	JWTPublicKey              string
	JWTIssuer                 string
	ServiceAuthToken          string
	AcademicsGRPCAddr         string
	IdentityGRPCAddr          string
	BeaconGRPCAddr            string
	GRPCDialTimeout           time.Duration
	RedisAddr                 string
	RedisPassword             string
	BuzzLightyearTTL          time.Duration
	SignatureChallengeTTL     time.Duration
	DeviceSignatureWindow     time.Duration
	NfcDebugEnabled           bool
	SignatureCloseJobEnabled  bool
	SignatureCloseJobInterval time.Duration
	SignatureCloseJobTimeout  time.Duration
}

func Load() Config {
	return Config{
		HTTPAddr:                  getenv("HTTP_ADDR", ":8083"),
		GRPCAddr:                  getenv("GRPC_ADDR", ":9093"),
		DatabaseURL:               getenv("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/attendance?sslmode=disable"),
		JWTPublicKey:              getenvKey("JWT_PUBLIC_KEY", ""),
		JWTIssuer:                 getenv("JWT_ISSUER", "semaphore-auth-identity"),
		ServiceAuthToken:          getenv("SERVICE_AUTH_TOKEN", ""),
		AcademicsGRPCAddr:         getenv("ACADEMICS_GRPC_ADDR", "127.0.0.1:9092"),
		IdentityGRPCAddr:          getenv("IDENTITY_GRPC_ADDR", "127.0.0.1:9091"),
		BeaconGRPCAddr:            getenv("BEACON_GRPC_ADDR", "127.0.0.1:9094"),
		GRPCDialTimeout:           getenvDuration("GRPC_DIAL_TIMEOUT", 5*time.Second),
		RedisAddr:                 getenv("REDIS_ADDR", ""),
		RedisPassword:             getenv("REDIS_PASSWORD", ""),
		BuzzLightyearTTL:          getenvDuration("BUZZLIGHTYEAR_TTL", 45*time.Second),
		SignatureChallengeTTL:     getenvDuration("SIGNATURE_CHALLENGE_TTL", 5*time.Minute),
		DeviceSignatureWindow:     getenvDuration("DEVICE_SIGNATURE_WINDOW", 30*time.Second),
		NfcDebugEnabled:           getenvBool("NFC_DEBUG_ENABLED", false),
		SignatureCloseJobEnabled:  getenvBool("SIGNATURE_CLOSE_JOB_ENABLED", true),
		SignatureCloseJobInterval: getenvDuration("SIGNATURE_CLOSE_JOB_INTERVAL", 1*time.Minute),
		SignatureCloseJobTimeout:  getenvDuration("SIGNATURE_CLOSE_JOB_TIMEOUT", 10*time.Second),
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

func getenvBool(key string, fallback bool) bool {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
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
