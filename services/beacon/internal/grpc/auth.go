package grpc

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"semaphore/beacon/internal/auth"
	"semaphore/beacon/internal/config"
)

type claimsKey struct{}

const serviceTokenHeader = "x-service-token"

func NewServiceAuthUnaryInterceptor(expectedToken string) (grpc.UnaryServerInterceptor, error) {
	if expectedToken == "" {
		return nil, errors.New("service auth token required")
	}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		token := serviceTokenFromMetadata(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing_service_token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			return nil, status.Error(codes.PermissionDenied, "invalid_service_token")
		}
		return handler(ctx, req)
	}, nil
}

func NewJWTUnaryInterceptor(cfg config.Config) (grpc.UnaryServerInterceptor, error) {
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	return NewJWTUnaryInterceptorWithKey(publicKey, cfg.JWTIssuer), nil
}

func NewJWTUnaryInterceptorWithKey(publicKey *rsa.PublicKey, issuer string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		token := bearerTokenFromMetadata(ctx)
		if token == "" {
			return handler(ctx, req)
		}
		claims, err := auth.ParseToken(publicKey, issuer, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid_token")
		}
		ctx = context.WithValue(ctx, claimsKey{}, claims)
		return handler(ctx, req)
	}
}

func ClaimsFromContext(ctx context.Context) *auth.Claims {
	value := ctx.Value(claimsKey{})
	claims, _ := value.(*auth.Claims)
	return claims
}

func RequireAdminOrDev(ctx context.Context) (*auth.Claims, error) {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return nil, status.Error(codes.Unauthenticated, "missing_token")
	}
	if claims.UserType != "admin" && claims.UserType != "dev" {
		return nil, status.Error(codes.PermissionDenied, "forbidden")
	}
	return claims, nil
}

func bearerTokenFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}
	return bearerToken(values[0])
}

func serviceTokenFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(serviceTokenHeader)
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func bearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
