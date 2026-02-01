package clients

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	academicsv1 "semaphore/academics/academics/v1"
	identityv1 "semaphore/auth-identity/identity/v1"
)

type Clients struct {
	AcademicsConn    *grpc.ClientConn
	IdentityConn     *grpc.ClientConn
	Academics        academicsv1.AcademicsQueryServiceClient
	AcademicsCommand academicsv1.AcademicsCommandServiceClient
	Identity         identityv1.IdentityQueryServiceClient
}

const serviceTokenHeader = "x-service-token"

func New(ctx context.Context, academicsAddr, identityAddr, serviceToken string, timeout time.Duration) (*Clients, error) {
	if serviceToken == "" {
		return nil, errors.New("service auth token required")
	}
	academicsConn, err := dial(ctx, academicsAddr, serviceToken, timeout)
	if err != nil {
		return nil, err
	}
	identityConn, err := dial(ctx, identityAddr, serviceToken, timeout)
	if err != nil {
		_ = academicsConn.Close()
		return nil, err
	}

	return &Clients{
		AcademicsConn:    academicsConn,
		IdentityConn:     identityConn,
		Academics:        academicsv1.NewAcademicsQueryServiceClient(academicsConn),
		AcademicsCommand: academicsv1.NewAcademicsCommandServiceClient(academicsConn),
		Identity:         identityv1.NewIdentityQueryServiceClient(identityConn),
	}, nil
}

func (c *Clients) Close() {
	if c == nil {
		return
	}
	if c.AcademicsConn != nil {
		_ = c.AcademicsConn.Close()
	}
	if c.IdentityConn != nil {
		_ = c.IdentityConn.Close()
	}
}

func dial(ctx context.Context, addr, serviceToken string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(serviceAuthUnaryClientInterceptor(serviceToken)),
	)
}

func serviceAuthUnaryClientInterceptor(serviceToken string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, serviceTokenHeader, serviceToken)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
