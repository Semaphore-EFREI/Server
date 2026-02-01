package clients

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	attendancev1 "semaphore/attendance/attendance/v1"
)

type Clients struct {
	AttendanceConn *grpc.ClientConn
	Attendance     attendancev1.AttendanceQueryServiceClient
}

func New(ctx context.Context, attendanceAddr string, timeout time.Duration) (*Clients, error) {
	attendanceConn, err := dial(ctx, attendanceAddr, timeout)
	if err != nil {
		return nil, err
	}
	return &Clients{
		AttendanceConn: attendanceConn,
		Attendance:     attendancev1.NewAttendanceQueryServiceClient(attendanceConn),
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

func dial(ctx context.Context, addr string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
