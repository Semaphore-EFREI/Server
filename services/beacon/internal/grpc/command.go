package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beaconv1 "semaphore/beacon/beacon/v1"
	"semaphore/beacon/internal/db"
	"semaphore/beacon/internal/operations"
)

type BeaconCommandServer struct {
	beaconv1.UnimplementedBeaconCommandServiceServer
	store *db.Store
}

func NewBeaconCommandServer(store *db.Store) *BeaconCommandServer {
	return &BeaconCommandServer{store: store}
}

func (s *BeaconCommandServer) AssignBeaconToClassroom(ctx context.Context, req *beaconv1.AssignBeaconToClassroomRequest) (*beaconv1.AssignBeaconToClassroomResponse, error) {
	if _, err := RequireAdminOrDev(ctx); err != nil {
		return nil, err
	}
	if err := operations.AssignBeaconToClassroom(ctx, s.store, req.GetBeaconId(), req.GetClassroomId()); err != nil {
		return nil, commandStatusFromError(err)
	}
	return &beaconv1.AssignBeaconToClassroomResponse{}, nil
}

func (s *BeaconCommandServer) RemoveBeaconFromClassroom(ctx context.Context, req *beaconv1.RemoveBeaconFromClassroomRequest) (*beaconv1.RemoveBeaconFromClassroomResponse, error) {
	if _, err := RequireAdminOrDev(ctx); err != nil {
		return nil, err
	}
	if err := operations.RemoveBeaconFromClassroom(ctx, s.store, req.GetBeaconId(), req.GetClassroomId()); err != nil {
		return nil, commandStatusFromError(err)
	}
	return &beaconv1.RemoveBeaconFromClassroomResponse{}, nil
}

func commandStatusFromError(err error) error {
	var opErr *operations.Error
	if !errors.As(err, &opErr) {
		return status.Error(codes.Internal, operations.ErrServerError)
	}
	switch opErr.Code {
	case operations.ErrInvalidBeaconID, operations.ErrMissingClassroomID, operations.ErrInvalidClassroomID:
		return status.Error(codes.InvalidArgument, opErr.Code)
	case operations.ErrBeaconNotFound, operations.ErrClassroomNotAssigned:
		return status.Error(codes.NotFound, opErr.Code)
	case operations.ErrClassroomAlreadyAssigned:
		return status.Error(codes.AlreadyExists, opErr.Code)
	case operations.ErrServerError:
		return status.Error(codes.Internal, opErr.Code)
	default:
		return status.Error(codes.Internal, operations.ErrServerError)
	}
}
