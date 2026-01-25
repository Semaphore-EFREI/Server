package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "semaphore/auth-identity/identity/v1"
	"semaphore/auth-identity/internal/repository"
)

type IdentityServer struct {
	identityv1.UnimplementedIdentityQueryServiceServer
	store *repository.Store
}

func NewIdentityServer(store *repository.Store) *IdentityServer {
	return &IdentityServer{store: store}
}

func (s *IdentityServer) GetUserLite(ctx context.Context, req *identityv1.GetUserLiteRequest) (*identityv1.GetUserLiteResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	user, err := s.store.GetUserByID(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	role, err := s.store.GetRole(ctx, user.ID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "role not found")
	}

	return &identityv1.GetUserLiteResponse{
		User: &identityv1.UserLite{
			Id:        user.ID,
			SchoolId:  user.SchoolID,
			Email:     user.Email,
			Firstname: user.FirstName,
			Lastname:  user.LastName,
			UserType:  role.UserType,
		},
	}, nil
}

func (s *IdentityServer) Exists(ctx context.Context, req *identityv1.ExistsRequest) (*identityv1.ExistsResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	exists, err := s.store.UserExists(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "lookup failed")
	}
	return &identityv1.ExistsResponse{Exists: exists}, nil
}

func (s *IdentityServer) ValidateStudentDevice(ctx context.Context, req *identityv1.ValidateStudentDeviceRequest) (*identityv1.ValidateStudentDeviceResponse, error) {
	if req.GetStudentId() == "" || req.GetDeviceIdentifier() == "" {
		return nil, status.Error(codes.InvalidArgument, "student_id and device_identifier required")
	}
	device, err := s.store.GetActiveDevice(ctx, req.GetStudentId())
	if err != nil || device.DeviceIdentifier != req.GetDeviceIdentifier() || !device.Active {
		return &identityv1.ValidateStudentDeviceResponse{IsValid: false}, nil
	}
	_ = s.store.UpdateDeviceLastSeen(ctx, device.ID, time.Now().UTC())
	return &identityv1.ValidateStudentDeviceResponse{IsValid: true}, nil
}
