package grpc

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

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
