package grpc

import (
	"context"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beaconv1 "semaphore/beacon/beacon/v1"
	"semaphore/beacon/internal/db"
)

type BeaconQueryServer struct {
	beaconv1.UnimplementedBeaconQueryServiceServer
	store *db.Store
}

func NewBeaconQueryServer(store *db.Store) *BeaconQueryServer {
	return &BeaconQueryServer{store: store}
}

func (s *BeaconQueryServer) ListBeaconsByClassroom(ctx context.Context, req *beaconv1.ListBeaconsByClassroomRequest) (*beaconv1.ListBeaconsByClassroomResponse, error) {
	if req.GetClassroomId() == "" {
		return nil, status.Error(codes.InvalidArgument, "classroom_id required")
	}
	classroomUUID, err := uuid.Parse(req.GetClassroomId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid classroom_id")
	}

	rows, err := s.store.Queries.ListBeaconsByClassroom(ctx, pgUUID(classroomUUID))
	if err != nil {
		return nil, status.Error(codes.Internal, "beacon lookup failed")
	}

	beacons := make([]*beaconv1.Beacon, 0, len(rows))
	for _, row := range rows {
		beacons = append(beacons, mapBeacon(row))
	}
	return &beaconv1.ListBeaconsByClassroomResponse{Beacons: beacons}, nil
}

func mapBeacon(row db.Beacon) *beaconv1.Beacon {
	serial := int64(0)
	if row.SerialNumber != "" {
		if parsed, err := strconv.ParseInt(row.SerialNumber, 10, 64); err == nil {
			serial = parsed
		}
	}

	resp := &beaconv1.Beacon{
		Id:             uuidString(row.ID),
		SerialNumber:   serial,
		ClassroomId:    uuidString(row.ClassroomID),
		ProgramVersion: row.ProgramVersion.String,
	}
	if !row.ProgramVersion.Valid {
		resp.ProgramVersion = ""
	}
	return resp
}

func uuidString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}
