package clients

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	attendancev1 "semaphore/attendance/attendance/v1"
)

type Clients struct {
	AttendanceConn *grpc.ClientConn
	Attendance     attendancev1.AttendanceCommandServiceClient
}

const serviceTokenHeader = "x-service-token"

func New(ctx context.Context, attendanceAddr, serviceToken string, timeout time.Duration) (*Clients, error) {
	if serviceToken == "" {
		return nil, errors.New("service auth token required")
	}
	conn, err := dial(ctx, attendanceAddr, serviceToken, timeout)
	if err != nil {
		return nil, err
	}

	return &Clients{
		AttendanceConn: conn,
		Attendance:     attendancev1.NewAttendanceCommandServiceClient(conn),
	}, nil
}

func (c *Clients) Close() {
	if c == nil {
		return
	}
	if c.AttendanceConn != nil {
		_ = c.AttendanceConn.Close()
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
