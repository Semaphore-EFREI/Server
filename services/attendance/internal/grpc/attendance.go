package grpc

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	academicsv1 "semaphore/academics/academics/v1"
	attendancev1 "semaphore/attendance/attendance/v1"
	"semaphore/attendance/internal/db"
)

type AttendanceServer struct {
	attendancev1.UnimplementedAttendanceCommandServiceServer
	store     *db.Store
	academics academicsv1.AcademicsQueryServiceClient
}

func NewAttendanceServer(store *db.Store, academics academicsv1.AcademicsQueryServiceClient) *AttendanceServer {
	return &AttendanceServer{store: store, academics: academics}
}

func (s *AttendanceServer) CreateSignatureAttempt(ctx context.Context, req *attendancev1.CreateSignatureAttemptRequest) (*attendancev1.CreateSignatureAttemptResponse, error) {
	if req.GetStudentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "student_id required")
	}
	if req.GetCourseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "course_id required")
	}
	studentUUID, err := uuid.Parse(req.GetStudentId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid student_id")
	}
	courseUUID, err := uuid.Parse(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}

	courseResp, err := s.academics.GetCourse(ctx, &academicsv1.GetCourseRequest{CourseId: req.GetCourseId()})
	if err != nil || courseResp.GetCourse() == nil {
		return nil, status.Error(codes.NotFound, "course not found")
	}
	course := courseResp.GetCourse()

	allowedResp, err := s.academics.ValidateStudentCourse(ctx, &academicsv1.ValidateStudentCourseRequest{
		StudentId: req.GetStudentId(),
		CourseId:  req.GetCourseId(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "validation failed")
	}

	signedAt := time.Now().UTC()
	if req.GetReceivedAt() != nil {
		signedAt = req.GetReceivedAt().AsTime().UTC()
	}

	statusValue, message := evaluateStatus(course, allowedResp.GetIsAllowed(), signedAt)
	methodValue, err := methodFromGRPC(req.GetMethod())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid method")
	}

	prefsResp, err := s.academics.GetSchoolPreferences(ctx, &academicsv1.GetSchoolPreferencesRequest{SchoolId: course.GetSchoolId()})
	if err != nil || prefsResp.GetPreferences() == nil {
		return nil, status.Error(codes.Internal, "preferences lookup failed")
	}
	if !methodAllowedForStudent(methodValue, prefsResp.GetPreferences()) {
		return &attendancev1.CreateSignatureAttemptResponse{
			SignatureId: "",
			Status:      attendancev1.SignatureStatus_SIGNATURE_STATUS_REFUSED,
			Message:     "method_not_allowed",
		}, nil
	}
	if !prefsResp.GetPreferences().GetStudentsCanSignBeforeTeacher() {
		present, err := s.store.Queries.HasTeacherPresence(ctx, pgUUID(courseUUID))
		if err != nil {
			return nil, status.Error(codes.Internal, "teacher presence lookup failed")
		}
		if !present {
			return &attendancev1.CreateSignatureAttemptResponse{
				SignatureId: "",
				Status:      attendancev1.SignatureStatus_SIGNATURE_STATUS_REFUSED,
				Message:     "teacher_not_present",
			}, nil
		}
	}

	signatureID := uuid.New()
	err = s.store.WithTx(ctx, func(q *db.Queries) error {
		_, err := q.CreateSignature(ctx, db.CreateSignatureParams{
			ID:        pgUUID(signatureID),
			CourseID:  pgUUID(courseUUID),
			SignedAt:  pgTime(signedAt),
			Status:    statusValue,
			Method:    methodValue,
			ImageUrl:  pgText(""),
			CreatedAt: nowPgTime(),
			UpdatedAt: nowPgTime(),
		})
		if err != nil {
			return err
		}
		return q.CreateStudentSignature(ctx, db.CreateStudentSignatureParams{
			SignatureID:     pgUUID(signatureID),
			StudentID:       pgUUID(studentUUID),
			TeacherID:       pgUUIDFromString(req.GetTeacherId()),
			AdministratorID: pgUUIDFromString(req.GetAdministratorId()),
		})
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "signature creation failed")
	}

	return &attendancev1.CreateSignatureAttemptResponse{
		SignatureId: signatureID.String(),
		Status:      statusToGRPC(statusValue),
		Message:     message,
	}, nil
}

func (s *AttendanceServer) DeleteStudentSignatures(ctx context.Context, req *attendancev1.DeleteStudentSignaturesRequest) (*attendancev1.DeleteStudentSignaturesResponse, error) {
	if req.GetStudentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "student_id required")
	}
	studentUUID, err := uuid.Parse(req.GetStudentId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid student_id")
	}

	var deletedCount int64
	err = s.store.WithTx(ctx, func(q *db.Queries) error {
		ids, err := q.ListActiveStudentSignatureIDs(ctx, pgUUID(studentUUID))
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			deletedCount = 0
			return nil
		}
		deletedAt := nowPgTime()
		if err := q.SoftDeleteSignaturesByStudent(ctx, db.SoftDeleteSignaturesByStudentParams{
			StudentID: pgUUID(studentUUID),
			DeletedAt: deletedAt,
		}); err != nil {
			return err
		}
		if err := q.SoftDeleteStudentSignaturesByStudent(ctx, db.SoftDeleteStudentSignaturesByStudentParams{
			StudentID: pgUUID(studentUUID),
			DeletedAt: deletedAt,
		}); err != nil {
			return err
		}
		deletedCount = int64(len(ids))
		return nil
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "delete failed")
	}

	return &attendancev1.DeleteStudentSignaturesResponse{DeletedCount: deletedCount}, nil
}

func evaluateStatus(course *academicsv1.Course, allowed bool, signedAt time.Time) (db.SignatureStatus, string) {
	if !allowed {
		return db.SignatureStatus("absent"), "student not enrolled"
	}
	if course.GetSignatureClosed() {
		return db.SignatureStatus("absent"), "signature closed"
	}
	start := course.GetStartAt().AsTime().UTC()
	end := course.GetEndAt().AsTime().UTC()
	if signedAt.Before(start) {
		return db.SignatureStatus("absent"), "too early"
	}
	if signedAt.After(end) {
		return db.SignatureStatus("absent"), "course ended"
	}
	closing := start.Add(time.Duration(course.GetSignatureClosingDelayMinutes()) * time.Minute)
	if signedAt.After(closing) {
		return db.SignatureStatus("late"), "late"
	}
	return db.SignatureStatus("present"), "accepted"
}

func methodFromGRPC(method attendancev1.SignatureMethod) (db.SignatureMethod, error) {
	switch method {
	case attendancev1.SignatureMethod_SIGNATURE_METHOD_NFC:
		return db.SignatureMethod("nfc"), nil
	case attendancev1.SignatureMethod_SIGNATURE_METHOD_FLASHLIGHT:
		return db.SignatureMethod("buzzLightyear"), nil
	case attendancev1.SignatureMethod_SIGNATURE_METHOD_BEACON:
		return db.SignatureMethod("beacon"), nil
	case attendancev1.SignatureMethod_SIGNATURE_METHOD_TEACHER:
		return db.SignatureMethod("teacher"), nil
	case attendancev1.SignatureMethod_SIGNATURE_METHOD_ADMIN:
		return db.SignatureMethod("admin"), nil
	default:
		return "", status.Error(codes.InvalidArgument, "unsupported method")
	}
}

func statusToGRPC(statusValue db.SignatureStatus) attendancev1.SignatureStatus {
	switch string(statusValue) {
	case "signed":
		return attendancev1.SignatureStatus_SIGNATURE_STATUS_PENDING
	case "present":
		return attendancev1.SignatureStatus_SIGNATURE_STATUS_ACCEPTED
	case "absent":
		return attendancev1.SignatureStatus_SIGNATURE_STATUS_REFUSED
	case "late":
		return attendancev1.SignatureStatus_SIGNATURE_STATUS_LATE
	default:
		return attendancev1.SignatureStatus_SIGNATURE_STATUS_UNSPECIFIED
	}
}

func methodAllowedForStudent(method db.SignatureMethod, prefs *academicsv1.SchoolPreferences) bool {
	switch string(method) {
	case "buzzLightyear", "beacon":
		return prefs.GetEnableFlash()
	case "nfc":
		return prefs.GetEnableNfc()
	default:
		return true
	}
}

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func pgUUIDFromString(id string) pgtype.UUID {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}
}

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func nowPgTime() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
}

func pgText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}
