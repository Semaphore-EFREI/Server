package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/academics/internal/db"
)

type AcademicsServer struct {
	academicsv1.UnimplementedAcademicsQueryServiceServer
	queries *db.Queries
}

func NewAcademicsServer(queries *db.Queries) *AcademicsServer {
	return &AcademicsServer{queries: queries}
}

func (s *AcademicsServer) GetCourse(ctx context.Context, req *academicsv1.GetCourseRequest) (*academicsv1.GetCourseResponse, error) {
	if req.GetCourseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "course_id required")
	}
	courseID, err := parseUUID(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}
	course, err := s.queries.GetCourse(ctx, courseID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "course not found")
	}

	return &academicsv1.GetCourseResponse{
		Course: &academicsv1.Course{
			Id:                           uuidString(course.ID),
			SchoolId:                     uuidString(course.SchoolID),
			Name:                         course.Name,
			StartAt:                      timestamppb.New(course.StartAt.Time),
			EndAt:                        timestamppb.New(course.EndAt.Time),
			IsOnline:                     course.IsOnline,
			SignatureClosingDelayMinutes: course.SignatureClosingDelayMinutes,
			SignatureClosed:              course.SignatureClosed,
		},
	}, nil
}

func (s *AcademicsServer) ValidateTeacherCourse(ctx context.Context, req *academicsv1.ValidateTeacherCourseRequest) (*academicsv1.ValidateTeacherCourseResponse, error) {
	teacherID, err := parseUUID(req.GetTeacherId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid teacher_id")
	}
	courseID, err := parseUUID(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}

	row, err := s.queries.ValidateTeacherCourse(ctx, db.ValidateTeacherCourseParams{TeacherID: teacherID, CourseID: courseID})
	if err != nil {
		return nil, status.Error(codes.Internal, "validation failed")
	}

	return &academicsv1.ValidateTeacherCourseResponse{IsAssigned: row}, nil
}

func (s *AcademicsServer) ValidateStudentCourse(ctx context.Context, req *academicsv1.ValidateStudentCourseRequest) (*academicsv1.ValidateStudentCourseResponse, error) {
	studentID, err := parseUUID(req.GetStudentId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid student_id")
	}
	courseID, err := parseUUID(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}

	row, err := s.queries.ValidateStudentCourse(ctx, db.ValidateStudentCourseParams{StudentID: studentID, CourseID: courseID})
	if err != nil {
		return nil, status.Error(codes.Internal, "validation failed")
	}

	return &academicsv1.ValidateStudentCourseResponse{IsAllowed: row}, nil
}

func (s *AcademicsServer) ValidateClassroomCourse(ctx context.Context, req *academicsv1.ValidateClassroomCourseRequest) (*academicsv1.ValidateClassroomCourseResponse, error) {
	classroomID, err := parseUUID(req.GetClassroomId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid classroom_id")
	}
	courseID, err := parseUUID(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}

	row, err := s.queries.ValidateClassroomCourse(ctx, db.ValidateClassroomCourseParams{ClassroomID: classroomID, CourseID: courseID})
	if err != nil {
		return nil, status.Error(codes.Internal, "validation failed")
	}

	return &academicsv1.ValidateClassroomCourseResponse{IsLinked: row}, nil
}
