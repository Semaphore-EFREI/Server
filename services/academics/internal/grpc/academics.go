package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/academics/internal/db"

	"github.com/jackc/pgx/v5/pgtype"
)

type AcademicsServer struct {
	academicsv1.UnimplementedAcademicsQueryServiceServer
	store *db.Store
}

func NewAcademicsServer(store *db.Store) *AcademicsServer {
	return &AcademicsServer{store: store}
}

func (s *AcademicsServer) GetCourse(ctx context.Context, req *academicsv1.GetCourseRequest) (*academicsv1.GetCourseResponse, error) {
	if req.GetCourseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "course_id required")
	}
	courseID, err := parseUUID(req.GetCourseId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid course_id")
	}
	course, err := s.store.Queries.GetCourse(ctx, courseID)
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

	row, err := s.store.Queries.ValidateTeacherCourse(ctx, db.ValidateTeacherCourseParams{TeacherID: teacherID, CourseID: courseID})
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

	row, err := s.store.Queries.ValidateStudentCourse(ctx, db.ValidateStudentCourseParams{StudentID: studentID, CourseID: courseID})
	if err != nil {
		return nil, status.Error(codes.Internal, "validation failed")
	}

	var matched []string
	if row {
		groupIDs, err := s.store.Queries.ListMatchedStudentCourseGroups(ctx, db.ListMatchedStudentCourseGroupsParams{
			StudentID: studentID,
			CourseID:  courseID,
		})
		if err != nil {
			return nil, status.Error(codes.Internal, "validation failed")
		}
		matched = make([]string, 0, len(groupIDs))
		for _, id := range groupIDs {
			matched = append(matched, uuidString(id))
		}
	}

	return &academicsv1.ValidateStudentCourseResponse{
		IsAllowed:       row,
		MatchedGroupIds: matched,
	}, nil
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

	row, err := s.store.Queries.ValidateClassroomCourse(ctx, db.ValidateClassroomCourseParams{ClassroomID: classroomID, CourseID: courseID})
	if err != nil {
		return nil, status.Error(codes.Internal, "validation failed")
	}

	return &academicsv1.ValidateClassroomCourseResponse{IsLinked: row}, nil
}

func (s *AcademicsServer) ListStudentGroupIds(ctx context.Context, req *academicsv1.ListStudentGroupIdsRequest) (*academicsv1.ListStudentGroupIdsResponse, error) {
	studentIDsInput := req.GetStudentIds()
	if len(studentIDsInput) == 0 {
		return nil, status.Error(codes.InvalidArgument, "student_ids required")
	}

	studentIDs := make([]string, 0, len(studentIDsInput))
	seen := make(map[string]struct{}, len(studentIDsInput))
	for _, studentID := range studentIDsInput {
		if studentID == "" {
			return nil, status.Error(codes.InvalidArgument, "invalid student_id")
		}
		parsed, err := parseUUID(studentID)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid student_id")
		}
		normalized := uuidString(parsed)
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		studentIDs = append(studentIDs, normalized)
	}

	var schoolID string
	if req.GetSchoolId() != "" {
		parsed, err := parseUUID(req.GetSchoolId())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid school_id")
		}
		schoolID = uuidString(parsed)
	}

	query := `
    SELECT sgs.student_id, sgs.student_group_id
    FROM students_groups sgs
    INNER JOIN student_groups sg ON sg.id = sgs.student_group_id
    WHERE sgs.student_id = ANY($1::uuid[]) AND sg.deleted_at IS NULL
  `
	args := []any{studentIDs}
	if schoolID != "" {
		query += " AND sg.school_id = $2"
		args = append(args, schoolID)
	}
	query += " ORDER BY sgs.student_id, sg.created_at DESC"

	rows, err := s.store.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, status.Error(codes.Internal, "query failed")
	}
	defer rows.Close()

	groupMap := make(map[string][]string, len(studentIDs))
	for _, id := range studentIDs {
		groupMap[id] = []string{}
	}

	for rows.Next() {
		var studentUUID pgtype.UUID
		var groupUUID pgtype.UUID
		if err := rows.Scan(&studentUUID, &groupUUID); err != nil {
			return nil, status.Error(codes.Internal, "query failed")
		}
		studentID := uuidString(studentUUID)
		groupMap[studentID] = append(groupMap[studentID], uuidString(groupUUID))
	}
	if err := rows.Err(); err != nil {
		return nil, status.Error(codes.Internal, "query failed")
	}

	resp := &academicsv1.ListStudentGroupIdsResponse{Students: make([]*academicsv1.StudentGroupIdsByStudent, 0, len(studentIDs))}
	for _, studentID := range studentIDs {
		resp.Students = append(resp.Students, &academicsv1.StudentGroupIdsByStudent{
			StudentId: studentID,
			GroupIds:  groupMap[studentID],
		})
	}
	return resp, nil
}

func (s *AcademicsServer) GetSchoolPreferences(ctx context.Context, req *academicsv1.GetSchoolPreferencesRequest) (*academicsv1.GetSchoolPreferencesResponse, error) {
	if req.GetSchoolId() == "" {
		return nil, status.Error(codes.InvalidArgument, "school_id required")
	}
	schoolID, err := parseUUID(req.GetSchoolId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid school_id")
	}
	school, err := s.store.Queries.GetSchool(ctx, schoolID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "school not found")
	}
	prefs, err := s.store.Queries.GetSchoolPreferences(ctx, school.PreferencesID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "preferences not found")
	}
	return &academicsv1.GetSchoolPreferencesResponse{
		Preferences: &academicsv1.SchoolPreferences{
			Id:                                  uuidString(prefs.ID),
			DefaultSignatureClosingDelayMinutes: prefs.DefaultSignatureClosingDelayMinutes,
			TeacherCanModifyClosingDelay:        prefs.TeacherCanModifyClosingDelay,
			StudentsCanSignBeforeTeacher:        prefs.StudentsCanSignBeforeTeacher,
			EnableFlash:                         prefs.EnableFlash,
			DisableCourseModificationFromUi:     prefs.DisableCourseModificationFromUi,
			EnableNfc:                           prefs.EnableNfc,
		},
	}, nil
}
