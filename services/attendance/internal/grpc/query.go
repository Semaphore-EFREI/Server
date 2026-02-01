package grpc

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	attendancev1 "semaphore/attendance/attendance/v1"
	"semaphore/attendance/internal/db"
)

type AttendanceQueryServer struct {
	attendancev1.UnimplementedAttendanceQueryServiceServer
	store *db.Store
}

func NewAttendanceQueryServer(store *db.Store) *AttendanceQueryServer {
	return &AttendanceQueryServer{store: store}
}

func (s *AttendanceQueryServer) ListCourseSignatures(ctx context.Context, req *attendancev1.ListCourseSignaturesRequest) (*attendancev1.ListCourseSignaturesResponse, error) {
	if req.GetCourseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "course_id required")
	}
	courseUUID, err := uuid.Parse(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}

	studentRows, err := s.store.Queries.ListStudentSignaturesByCourse(ctx, db.ListStudentSignaturesByCourseParams{
		CourseID: pgUUID(courseUUID),
		Limit:    500,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "student signatures lookup failed")
	}
	teacherRows, err := s.store.Queries.ListTeacherSignaturesByCourse(ctx, db.ListTeacherSignaturesByCourseParams{
		CourseID: pgUUID(courseUUID),
		Limit:    500,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "teacher signatures lookup failed")
	}

	studentSigs := make([]*attendancev1.StudentSignature, 0, len(studentRows))
	for _, row := range studentRows {
		studentSigs = append(studentSigs, mapStudentSignature(row))
	}
	teacherSigs := make([]*attendancev1.TeacherSignature, 0, len(teacherRows))
	for _, row := range teacherRows {
		teacherSigs = append(teacherSigs, mapTeacherSignature(row))
	}

	return &attendancev1.ListCourseSignaturesResponse{
		StudentSignatures: studentSigs,
		TeacherSignatures: teacherSigs,
	}, nil
}

func mapStudentSignature(row db.ListStudentSignaturesByCourseRow) *attendancev1.StudentSignature {
	resp := &attendancev1.StudentSignature{
		Id:              uuidString(row.ID),
		CourseId:        uuidString(row.CourseID),
		SignedAt:        timestamppb.New(row.SignedAt.Time),
		Status:          string(row.Status),
		Method:          string(row.Method),
		StudentId:       uuidString(row.StudentID),
		TeacherId:       uuidString(row.TeacherID),
		AdministratorId: uuidString(row.AdministratorID),
	}
	if row.ImageUrl.Valid {
		resp.Image = row.ImageUrl.String
	}
	return resp
}

func mapTeacherSignature(row db.ListTeacherSignaturesByCourseRow) *attendancev1.TeacherSignature {
	resp := &attendancev1.TeacherSignature{
		Id:              uuidString(row.ID),
		CourseId:        uuidString(row.CourseID),
		SignedAt:        timestamppb.New(row.SignedAt.Time),
		Status:          string(row.Status),
		Method:          string(row.Method),
		TeacherId:       uuidString(row.TeacherID),
		AdministratorId: uuidString(row.AdministratorID),
	}
	if row.ImageUrl.Valid {
		resp.Image = row.ImageUrl.String
	}
	return resp
}

func uuidString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}
