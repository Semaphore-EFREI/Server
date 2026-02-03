package grpc

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/academics/internal/db"
)

type AcademicsCommandServer struct {
	academicsv1.UnimplementedAcademicsCommandServiceServer
	queries *db.Queries
}

func NewAcademicsCommandServer(queries *db.Queries) *AcademicsCommandServer {
	return &AcademicsCommandServer{queries: queries}
}

func (s *AcademicsCommandServer) CloseExpiredCourses(ctx context.Context, req *academicsv1.CloseExpiredCoursesRequest) (*academicsv1.CloseExpiredCoursesResponse, error) {
	now := time.Now().UTC()
	if req.GetNow() != nil {
		now = req.GetNow().AsTime().UTC()
	}
	count, err := s.queries.CloseExpiredCourses(ctx, pgTime(now))
	if err != nil {
		return nil, status.Error(codes.Internal, "close failed")
	}
	return &academicsv1.CloseExpiredCoursesResponse{ClosedCount: count}, nil
}

func (s *AcademicsCommandServer) RemoveStudentFromGroups(ctx context.Context, req *academicsv1.RemoveStudentFromGroupsRequest) (*academicsv1.RemoveStudentFromGroupsResponse, error) {
	if req.GetStudentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "student_id required")
	}
	studentID, err := requireUUID(req.GetStudentId(), "student_id")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid student_id")
	}
	count, err := s.queries.RemoveStudentFromGroups(ctx, studentID)
	if err != nil {
		return nil, status.Error(codes.Internal, "remove failed")
	}
	return &academicsv1.RemoveStudentFromGroupsResponse{RemovedCount: count}, nil
}

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}
