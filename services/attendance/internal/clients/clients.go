package clients

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

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

func New(ctx context.Context, academicsAddr, identityAddr string, timeout time.Duration) (*Clients, error) {
	academicsConn, err := dial(ctx, academicsAddr, timeout)
	if err != nil {
		return nil, err
	}
	identityConn, err := dial(ctx, identityAddr, timeout)
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

func dial(ctx context.Context, addr string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
