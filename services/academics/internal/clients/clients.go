package clients

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	attendancev1 "semaphore/attendance/attendance/v1"
	beaconv1 "semaphore/beacon/beacon/v1"
)

type Clients struct {
	AttendanceConn *grpc.ClientConn
	Attendance     attendancev1.AttendanceQueryServiceClient
	BeaconConn     *grpc.ClientConn
	Beacon         beaconv1.BeaconQueryServiceClient
}

func New(ctx context.Context, attendanceAddr, beaconAddr string, timeout time.Duration) (*Clients, error) {
	attendanceConn, err := dial(ctx, attendanceAddr, timeout)
	if err != nil {
		return nil, err
	}
	beaconConn, err := dial(ctx, beaconAddr, timeout)
	if err != nil {
		_ = attendanceConn.Close()
		return nil, err
	}
	return &Clients{
		AttendanceConn: attendanceConn,
		Attendance:     attendancev1.NewAttendanceQueryServiceClient(attendanceConn),
		BeaconConn:     beaconConn,
		Beacon:         beaconv1.NewBeaconQueryServiceClient(beaconConn),
	}, nil
}

func (c *Clients) Close() {
	if c == nil {
		return
	}
	if c.AttendanceConn != nil {
		_ = c.AttendanceConn.Close()
	}
	if c.BeaconConn != nil {
		_ = c.BeaconConn.Close()
	}
}

func dial(ctx context.Context, addr string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
