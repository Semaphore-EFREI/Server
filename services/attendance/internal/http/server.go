package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/attendance/internal/auth"
	"semaphore/attendance/internal/config"
	"semaphore/attendance/internal/db"
	identityv1 "semaphore/auth-identity/identity/v1"
)

type Server struct {
	cfg          config.Config
	store        *db.Store
	academics    academicsv1.AcademicsQueryServiceClient
	identity     identityv1.IdentityQueryServiceClient
	jwtPublicKey *rsa.PublicKey
	redis        *redis.Client
	buzzTTL      time.Duration
}

func NewServer(cfg config.Config, store *db.Store, academics academicsv1.AcademicsQueryServiceClient, identity identityv1.IdentityQueryServiceClient, redisClient *redis.Client) (*Server, error) {
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		store:        store,
		academics:    academics,
		identity:     identity,
		jwtPublicKey: publicKey,
		redis:        redisClient,
		buzzTTL:      cfg.BuzzLightyearTTL,
	}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.With(s.authMiddleware).Get("/course/{courseId}/status", s.handleGetCourseStatus)
	r.With(s.authMiddleware).Post("/signature", s.handleCreateSignature)
	r.With(s.authMiddleware).Get("/signature/{signatureId}", s.handleGetSignature)
	r.With(s.authMiddleware).Get("/signature/buzzlightyear", s.handleGetBuzzlightyear)
	r.With(s.authMiddleware).Patch("/signature/{signatureId}", s.handlePatchSignature)
	r.With(s.authMiddleware).Delete("/signature/{signatureId}", s.handleDeleteSignature)
	r.With(s.authMiddleware).Get("/signatures", s.handleListSignatures)
	r.With(s.authMiddleware).Get("/signatures/report", s.handleSignatureReport)

	return r
}

// Auth

type claimsKey struct{}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing_token")
			return
		}
		claims, err := auth.ParseToken(s.jwtPublicKey, s.cfg.JWTIssuer, token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func claimsFromContext(ctx context.Context) *auth.Claims {
	value := ctx.Value(claimsKey{})
	claims, _ := value.(*auth.Claims)
	return claims
}

// Models

type signatureBaseResponse struct {
	ID     string `json:"id"`
	Date   int64  `json:"date"`
	Course string `json:"course"`
	Status string `json:"status"`
	Method string `json:"method"`
	Image  string `json:"image,omitempty"`
}

type studentSignatureResponse struct {
	signatureBaseResponse
	Student       string `json:"student"`
	Teacher       string `json:"teacher,omitempty"`
	Administrator string `json:"administrator,omitempty"`
}

type teacherSignatureResponse struct {
	signatureBaseResponse
	Teacher string `json:"teacher"`
}

type createSignatureRequest struct {
	Date          int64   `json:"date"`
	Course        string  `json:"course"`
	Status        string  `json:"status"`
	Image         *string `json:"image"`
	Method        string  `json:"method"`
	Student       string  `json:"student"`
	Teacher       string  `json:"teacher"`
	Administrator string  `json:"administrator"`
}

type patchSignatureRequest struct {
	Status        *string `json:"status"`
	Image         *string `json:"image"`
	Administrator *string `json:"administrator"`
}

// Handlers

func (s *Server) handleCreateSignature(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" && claims.UserType != "teacher" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req createSignatureRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.Date == 0 || req.Course == "" || req.Status == "" || req.Method == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if claims.UserType == "student" {
		if req.Student == "" {
			req.Student = claims.UserID
		}
		if req.Student != claims.UserID || req.Teacher != "" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		req.Administrator = ""
		if !s.validateStudentDevice(r.Context(), req.Student, r.Header.Get("X-Device-ID")) {
			writeError(w, http.StatusForbidden, "device_not_allowed")
			return
		}
	} else {
		if req.Teacher == "" {
			req.Teacher = claims.UserID
		}
		if req.Teacher != claims.UserID || req.Student != "" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		req.Administrator = ""
		if req.Image == nil || *req.Image == "" {
			writeError(w, http.StatusBadRequest, "missing_image")
			return
		}
	}

	courseID, err := parseUUID(req.Course)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course")
		return
	}

	courseResp, err := s.academics.GetCourse(r.Context(), &academicsv1.GetCourseRequest{CourseId: req.Course})
	if err != nil || courseResp.GetCourse() == nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	course := courseResp.GetCourse()

	if claims.UserType == "student" {
		allowed, err := s.academics.ValidateStudentCourse(r.Context(), &academicsv1.ValidateStudentCourseRequest{
			StudentId: req.Student,
			CourseId:  req.Course,
		})
		if err != nil || !allowed.GetIsAllowed() {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	} else {
		allowed, err := s.academics.ValidateTeacherCourse(r.Context(), &academicsv1.ValidateTeacherCourseRequest{
			TeacherId: req.Teacher,
			CourseId:  req.Course,
		})
		if err != nil || !allowed.GetIsAssigned() {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	}

	signedAt := time.Unix(req.Date, 0).UTC()
	statusValue, err := normalizeStatus(req.Status)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_status")
		return
	}
	methodValue, err := normalizeMethod(req.Method)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_method")
		return
	}

	if claims.UserType == "student" {
		prefs, err := s.loadSchoolPreferences(r.Context(), course.GetSchoolId())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "preferences_not_found")
			return
		}
		if !methodAllowedForStudent(methodValue, prefs) {
			writeError(w, http.StatusForbidden, "method_not_allowed")
			return
		}
		if !prefs.GetStudentsCanSignBeforeTeacher() {
			present, err := s.store.Queries.HasTeacherPresence(r.Context(), courseID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			if !present {
				writeError(w, http.StatusForbidden, "teacher_not_present")
				return
			}
		}
	}

	timingStatus, timingErr := validateTiming(course, signedAt)
	if timingErr != "" {
		writeError(w, http.StatusForbidden, timingErr)
		return
	}
	if timingStatus != "" {
		statusValue = db.SignatureStatus(timingStatus)
	}

	if claims.UserType == "student" {
		studentUUID, err := parseUUID(req.Student)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_student_id")
			return
		}
		rows, err := s.store.Queries.ListStudentSignaturesByStudentAndCourse(r.Context(), db.ListStudentSignaturesByStudentAndCourseParams{
			StudentID: studentUUID,
			CourseID:  courseID,
			Limit:     1,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if len(rows) > 0 {
			writeError(w, http.StatusConflict, "signature_exists")
			return
		}
	} else {
		teacherUUID, err := parseUUID(req.Teacher)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_teacher_id")
			return
		}
		rows, err := s.store.Queries.ListTeacherSignaturesByTeacherAndCourse(r.Context(), db.ListTeacherSignaturesByTeacherAndCourseParams{
			TeacherID: teacherUUID,
			CourseID:  courseID,
			Limit:     1,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if len(rows) > 0 {
			writeError(w, http.StatusConflict, "signature_exists")
			return
		}
	}

	signatureID := uuid.New()
	if err := s.store.WithTx(r.Context(), func(q *db.Queries) error {
		_, err := q.CreateSignature(r.Context(), db.CreateSignatureParams{
			ID:        pgUUID(signatureID),
			CourseID:  courseID,
			SignedAt:  pgTime(signedAt),
			Status:    statusValue,
			Method:    methodValue,
			ImageUrl:  pgText(req.Image),
			CreatedAt: nowPgTime(),
			UpdatedAt: nowPgTime(),
		})
		if err != nil {
			return err
		}
		if claims.UserType == "student" {
			return q.CreateStudentSignature(r.Context(), db.CreateStudentSignatureParams{
				SignatureID:     pgUUID(signatureID),
				StudentID:       pgUUIDFromString(req.Student),
				TeacherID:       pgUUIDFromString(req.Teacher),
				AdministratorID: pgUUIDFromString(req.Administrator),
				CourseID:        courseID,
			})
		}
		return q.CreateTeacherSignature(r.Context(), db.CreateTeacherSignatureParams{
			SignatureID: pgUUID(signatureID),
			TeacherID:   pgUUIDFromString(req.Teacher),
			CourseID:    courseID,
		})
	}); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "signature_exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if claims.UserType == "student" {
		resp := studentSignatureResponse{
			signatureBaseResponse: signatureBaseResponse{
				ID:     signatureID.String(),
				Date:   signedAt.Unix(),
				Course: req.Course,
				Status: string(statusValue),
				Method: string(methodValue),
			},
			Student:       req.Student,
			Teacher:       req.Teacher,
			Administrator: req.Administrator,
		}
		if req.Image != nil {
			resp.Image = *req.Image
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp := teacherSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     signatureID.String(),
			Date:   signedAt.Unix(),
			Course: req.Course,
			Status: string(statusValue),
			Method: string(methodValue),
		},
		Teacher: req.Teacher,
	}
	if req.Image != nil {
		resp.Image = *req.Image
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetSignature(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	signatureID := chi.URLParam(r, "signatureId")
	sigUUID, err := parseUUID(signatureID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_signature_id")
		return
	}

	studentSig, err := s.store.Queries.GetStudentSignature(r.Context(), sigUUID)
	if err == nil {
		if !s.canAccessStudentSignature(r.Context(), claims, studentSig.StudentID, studentSig.CourseID) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		resp := mapStudentSignature(studentSig)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	teacherSig, err := s.store.Queries.GetTeacherSignature(r.Context(), sigUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "signature_not_found")
		return
	}
	if !s.canAccessTeacherSignature(r.Context(), claims, teacherSig.TeacherID, teacherSig.CourseID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, mapTeacherSignature(teacherSig))
}

func (s *Server) handleGetCourseStatus(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" && claims.UserType != "teacher" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	courseID := chi.URLParam(r, "courseId")
	if courseID == "" {
		writeError(w, http.StatusBadRequest, "missing_course")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course")
		return
	}

	switch claims.UserType {
	case "student":
		allowed, err := s.academics.ValidateStudentCourse(r.Context(), &academicsv1.ValidateStudentCourseRequest{
			StudentId: claims.UserID,
			CourseId:  courseID,
		})
		if err != nil || !allowed.GetIsAllowed() {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		studentUUID, err := parseUUID(claims.UserID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_student_id")
			return
		}
		rows, err := s.store.Queries.ListStudentSignaturesByStudentAndCourse(r.Context(), db.ListStudentSignaturesByStudentAndCourseParams{
			StudentID: studentUUID,
			CourseID:  courseUUID,
			Limit:     1,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if len(rows) == 0 {
			writeError(w, http.StatusNotFound, "signature_not_found")
			return
		}
		writeJSON(w, http.StatusOK, mapStudentSignatureFromListStudentCourse(rows[0]))
		return
	case "teacher":
		allowed, err := s.academics.ValidateTeacherCourse(r.Context(), &academicsv1.ValidateTeacherCourseRequest{
			TeacherId: claims.UserID,
			CourseId:  courseID,
		})
		if err != nil || !allowed.GetIsAssigned() {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		teacherUUID, err := parseUUID(claims.UserID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_teacher_id")
			return
		}
		rows, err := s.store.Queries.ListTeacherSignaturesByTeacherAndCourse(r.Context(), db.ListTeacherSignaturesByTeacherAndCourseParams{
			TeacherID: teacherUUID,
			CourseID:  courseUUID,
			Limit:     1,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if len(rows) == 0 {
			writeError(w, http.StatusNotFound, "signature_not_found")
			return
		}
		writeJSON(w, http.StatusOK, mapTeacherSignatureFromListTeacherCourse(rows[0]))
		return
	default:
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
}

func (s *Server) handleGetBuzzlightyear(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	code, err := randomBuzzLightyearCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := s.storeBuzzLightyearCode(r.Context(), code); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]int32{
		"code":     code,
		"validity": 15,
	})
}

func (s *Server) handlePatchSignature(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType == "dev" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	signatureID := chi.URLParam(r, "signatureId")
	sigUUID, err := parseUUID(signatureID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_signature_id")
		return
	}

	var req patchSignatureRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	studentSig, err := s.store.Queries.GetStudentSignature(r.Context(), sigUUID)
	if err == nil {
		if err := s.applyStudentSignaturePatch(r.Context(), claims, studentSig, req); err != nil {
			writeError(w, err.status, err.code)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	teacherSig, err := s.store.Queries.GetTeacherSignature(r.Context(), sigUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "signature_not_found")
		return
	}
	if err := s.applyTeacherSignaturePatch(r.Context(), claims, teacherSig, req); err != nil {
		writeError(w, err.status, err.code)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSignature(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "admin" && claims.UserType != "dev" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	signatureID := chi.URLParam(r, "signatureId")
	sigUUID, err := parseUUID(signatureID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_signature_id")
		return
	}

	if _, err := s.store.Queries.GetStudentSignature(r.Context(), sigUUID); err != nil {
		if _, err := s.store.Queries.GetTeacherSignature(r.Context(), sigUUID); err != nil {
			writeError(w, http.StatusNotFound, "signature_not_found")
			return
		}
	}
	if err := s.store.Queries.SoftDeleteSignature(r.Context(), db.SoftDeleteSignatureParams{ID: sigUUID, DeletedAt: nowPgTime()}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSignatures(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	courseID := r.URL.Query().Get("courseId")
	studentID := r.URL.Query().Get("studentId")
	teacherID := r.URL.Query().Get("teacherId")
	limit := parseLimit(r, 50)

	var courseUUID pgtype.UUID
	if courseID != "" {
		parsed, err := parseUUID(courseID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_course")
			return
		}
		courseUUID = parsed
	}

	switch claims.UserType {
	case "student":
		if teacherID != "" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if studentID != "" && studentID != claims.UserID {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		studentID = claims.UserID
		studentUUID, err := parseUUID(studentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_student_id")
			return
		}
		if courseID != "" {
			rows, err := s.store.Queries.ListStudentSignaturesByStudentAndCourse(r.Context(), db.ListStudentSignaturesByStudentAndCourseParams{
				StudentID: studentUUID,
				CourseID:  courseUUID,
				Limit:     limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			resp := make([]any, 0, len(rows))
			for _, row := range rows {
				resp = append(resp, mapStudentSignatureFromListStudentCourse(row))
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		rows, err := s.store.Queries.ListStudentSignaturesByStudent(r.Context(), db.ListStudentSignaturesByStudentParams{
			StudentID: studentUUID,
			Limit:     limit,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		resp := make([]any, 0, len(rows))
		for _, row := range rows {
			resp = append(resp, mapStudentSignatureFromListStudent(row))
		}
		writeJSON(w, http.StatusOK, resp)
		return
	case "teacher":
		if studentID != "" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if teacherID != "" && teacherID != claims.UserID {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		teacherID = claims.UserID
		teacherUUID, err := parseUUID(teacherID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_teacher_id")
			return
		}
		if courseID != "" {
			allowed, err := s.academics.ValidateTeacherCourse(r.Context(), &academicsv1.ValidateTeacherCourseRequest{
				TeacherId: teacherID,
				CourseId:  courseID,
			})
			if err != nil || !allowed.GetIsAssigned() {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			studentRows, err := s.store.Queries.ListStudentSignaturesByCourse(r.Context(), db.ListStudentSignaturesByCourseParams{
				CourseID: courseUUID,
				Limit:    limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			teacherRows, err := s.store.Queries.ListTeacherSignaturesByCourse(r.Context(), db.ListTeacherSignaturesByCourseParams{
				CourseID: courseUUID,
				Limit:    limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			resp := make([]any, 0, len(studentRows)+len(teacherRows))
			for _, row := range studentRows {
				resp = append(resp, mapStudentSignatureFromListCourse(row))
			}
			for _, row := range teacherRows {
				resp = append(resp, mapTeacherSignatureFromListCourse(row))
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		rows, err := s.store.Queries.ListTeacherSignaturesByTeacher(r.Context(), db.ListTeacherSignaturesByTeacherParams{
			TeacherID: teacherUUID,
			Limit:     limit,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		resp := make([]any, 0, len(rows))
		for _, row := range rows {
			resp = append(resp, mapTeacherSignatureFromListTeacher(row))
		}
		writeJSON(w, http.StatusOK, resp)
		return
	case "admin", "dev":
		if courseID != "" {
			studentRows, err := s.store.Queries.ListStudentSignaturesByCourse(r.Context(), db.ListStudentSignaturesByCourseParams{
				CourseID: courseUUID,
				Limit:    limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			teacherRows, err := s.store.Queries.ListTeacherSignaturesByCourse(r.Context(), db.ListTeacherSignaturesByCourseParams{
				CourseID: courseUUID,
				Limit:    limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			resp := make([]any, 0, len(studentRows)+len(teacherRows))
			for _, row := range studentRows {
				resp = append(resp, mapStudentSignatureFromListCourse(row))
			}
			for _, row := range teacherRows {
				resp = append(resp, mapTeacherSignatureFromListCourse(row))
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if studentID != "" {
			studentUUID, err := parseUUID(studentID)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_student_id")
				return
			}
			rows, err := s.store.Queries.ListStudentSignaturesByStudent(r.Context(), db.ListStudentSignaturesByStudentParams{
				StudentID: studentUUID,
				Limit:     limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			resp := make([]any, 0, len(rows))
			for _, row := range rows {
				resp = append(resp, mapStudentSignatureFromListStudent(row))
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if teacherID != "" {
			teacherUUID, err := parseUUID(teacherID)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_teacher_id")
				return
			}
			rows, err := s.store.Queries.ListTeacherSignaturesByTeacher(r.Context(), db.ListTeacherSignaturesByTeacherParams{
				TeacherID: teacherUUID,
				Limit:     limit,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			resp := make([]any, 0, len(rows))
			for _, row := range rows {
				resp = append(resp, mapTeacherSignatureFromListTeacher(row))
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		writeError(w, http.StatusBadRequest, "missing_filter")
		return
	default:
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
}

type signatureReportResponse struct {
	Course        string           `json:"course"`
	StudentCounts map[string]int64 `json:"studentCounts"`
	TeacherCount  int64            `json:"teacherCount"`
}

func (s *Server) handleSignatureReport(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	courseID := r.URL.Query().Get("courseId")
	if courseID == "" {
		writeError(w, http.StatusBadRequest, "missing_course")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course")
		return
	}
	if claims.UserType == "teacher" {
		allowed, err := s.academics.ValidateTeacherCourse(r.Context(), &academicsv1.ValidateTeacherCourseRequest{
			TeacherId: claims.UserID,
			CourseId:  courseID,
		})
		if err != nil || !allowed.GetIsAssigned() {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	if claims.UserType == "student" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	rows, err := s.store.Queries.CountStudentSignatureStatusByCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	counts := make(map[string]int64)
	for _, row := range rows {
		counts[string(row.Status)] = row.Total
	}
	teacherCount, err := s.store.Queries.CountTeacherSignaturesByCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, signatureReportResponse{
		Course:        courseID,
		StudentCounts: counts,
		TeacherCount:  teacherCount,
	})
}

// Patch helpers

type patchError struct {
	status int
	code   string
}

func (s *Server) applyStudentSignaturePatch(ctx context.Context, claims *auth.Claims, sig db.GetStudentSignatureRow, req patchSignatureRequest) *patchError {
	if claims.UserType == "student" {
		if claims.UserID != uuidString(sig.StudentID) {
			return &patchError{status: http.StatusForbidden, code: "forbidden"}
		}
		if req.Status == nil {
			return &patchError{status: http.StatusBadRequest, code: "missing_status"}
		}
		statusValue, err := normalizeStatus(*req.Status)
		if err != nil {
			return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
		}
		if err := s.updateSignature(ctx, sig.ID, statusValue, sig.Method, sig.ImageUrl, sig.SignedAt.Time); err != nil {
			return &patchError{status: http.StatusInternalServerError, code: "server_error"}
		}
		return nil
	}
	if claims.UserType == "teacher" {
		allowed, err := s.academics.ValidateTeacherCourse(ctx, &academicsv1.ValidateTeacherCourseRequest{
			TeacherId: claims.UserID,
			CourseId:  uuidString(sig.CourseID),
		})
		if err != nil || !allowed.GetIsAssigned() {
			return &patchError{status: http.StatusForbidden, code: "forbidden"}
		}
		if req.Image != nil && *req.Image != "" {
			return &patchError{status: http.StatusForbidden, code: "forbidden"}
		}
		statusValue := sig.Status
		if req.Status != nil {
			parsed, err := normalizeStatus(*req.Status)
			if err != nil {
				return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
			}
			statusValue = parsed
		}
		imageValue := sig.ImageUrl
		if req.Image != nil && *req.Image == "" {
			imageValue = pgtype.Text{}
		}
		if err := s.updateSignature(ctx, sig.ID, statusValue, sig.Method, imageValue, sig.SignedAt.Time); err != nil {
			return &patchError{status: http.StatusInternalServerError, code: "server_error"}
		}
		_ = s.store.Queries.UpdateStudentSignature(ctx, db.UpdateStudentSignatureParams{
			SignatureID:     sig.ID,
			TeacherID:       pgUUIDFromString(claims.UserID),
			AdministratorID: sig.AdministratorID,
		})
		return nil
	}
	if claims.UserType == "admin" {
		statusValue := sig.Status
		if req.Status != nil {
			parsed, err := normalizeStatus(*req.Status)
			if err != nil {
				return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
			}
			statusValue = parsed
		}
		if err := s.updateSignature(ctx, sig.ID, statusValue, sig.Method, sig.ImageUrl, sig.SignedAt.Time); err != nil {
			return &patchError{status: http.StatusInternalServerError, code: "server_error"}
		}
		_ = s.store.Queries.UpdateStudentSignature(ctx, db.UpdateStudentSignatureParams{
			SignatureID:     sig.ID,
			TeacherID:       sig.TeacherID,
			AdministratorID: pgUUIDFromString(claims.UserID),
		})
		return nil
	}
	return &patchError{status: http.StatusForbidden, code: "forbidden"}
}

func (s *Server) applyTeacherSignaturePatch(ctx context.Context, claims *auth.Claims, sig db.GetTeacherSignatureRow, req patchSignatureRequest) *patchError {
	if claims.UserType == "teacher" {
		if claims.UserID != uuidString(sig.TeacherID) {
			return &patchError{status: http.StatusForbidden, code: "forbidden"}
		}
		statusValue := sig.Status
		if req.Status != nil {
			parsed, err := normalizeStatus(*req.Status)
			if err != nil {
				return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
			}
			statusValue = parsed
		}
		imageValue := sig.ImageUrl
		if req.Image != nil {
			imageValue = pgText(req.Image)
		}
		if err := s.updateSignature(ctx, sig.ID, statusValue, sig.Method, imageValue, sig.SignedAt.Time); err != nil {
			return &patchError{status: http.StatusInternalServerError, code: "server_error"}
		}
		return nil
	}
	if claims.UserType == "admin" {
		statusValue := sig.Status
		if req.Status != nil {
			parsed, err := normalizeStatus(*req.Status)
			if err != nil {
				return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
			}
			statusValue = parsed
		}
		if err := s.updateSignature(ctx, sig.ID, statusValue, sig.Method, sig.ImageUrl, sig.SignedAt.Time); err != nil {
			return &patchError{status: http.StatusInternalServerError, code: "server_error"}
		}
		return nil
	}
	if claims.UserType == "student" {
		return &patchError{status: http.StatusForbidden, code: "forbidden"}
	}
	return &patchError{status: http.StatusForbidden, code: "forbidden"}
}

func (s *Server) updateSignature(ctx context.Context, id pgtype.UUID, status db.SignatureStatus, method db.SignatureMethod, image pgtype.Text, signedAt time.Time) error {
	_, err := s.store.Queries.UpdateSignature(ctx, db.UpdateSignatureParams{
		ID:        id,
		Status:    status,
		Method:    method,
		ImageUrl:  image,
		SignedAt:  pgTime(signedAt),
		UpdatedAt: nowPgTime(),
	})
	return err
}

// Access helpers

func (s *Server) canAccessStudentSignature(ctx context.Context, claims *auth.Claims, studentID pgtype.UUID, courseID pgtype.UUID) bool {
	if claims.UserType == "dev" || claims.UserType == "admin" {
		return true
	}
	if claims.UserType == "student" {
		return claims.UserID == uuidString(studentID)
	}
	if claims.UserType == "teacher" {
		allowed, err := s.academics.ValidateTeacherCourse(ctx, &academicsv1.ValidateTeacherCourseRequest{
			TeacherId: claims.UserID,
			CourseId:  uuidString(courseID),
		})
		return err == nil && allowed.GetIsAssigned()
	}
	return false
}

func (s *Server) canAccessTeacherSignature(ctx context.Context, claims *auth.Claims, teacherID pgtype.UUID, courseID pgtype.UUID) bool {
	if claims.UserType == "dev" || claims.UserType == "admin" {
		return true
	}
	if claims.UserType == "teacher" {
		return claims.UserID == uuidString(teacherID)
	}
	if claims.UserType == "student" {
		return false
	}
	return false
}

// Mapping helpers

func mapStudentSignature(sig db.GetStudentSignatureRow) studentSignatureResponse {
	return mapStudentSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.StudentID, sig.TeacherID, sig.AdministratorID)
}

func mapStudentSignatureFromListStudent(sig db.ListStudentSignaturesByStudentRow) studentSignatureResponse {
	return mapStudentSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.StudentID, sig.TeacherID, sig.AdministratorID)
}

func mapStudentSignatureFromListStudentCourse(sig db.ListStudentSignaturesByStudentAndCourseRow) studentSignatureResponse {
	return mapStudentSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.StudentID, sig.TeacherID, sig.AdministratorID)
}

func mapStudentSignatureFromListCourse(sig db.ListStudentSignaturesByCourseRow) studentSignatureResponse {
	return mapStudentSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.StudentID, sig.TeacherID, sig.AdministratorID)
}

func mapStudentSignatureValues(id, courseID pgtype.UUID, signedAt pgtype.Timestamptz, status db.SignatureStatus, method db.SignatureMethod, image pgtype.Text, studentID, teacherID, adminID pgtype.UUID) studentSignatureResponse {
	resp := studentSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     uuidString(id),
			Date:   signedAt.Time.Unix(),
			Course: uuidString(courseID),
			Status: string(status),
			Method: string(method),
		},
		Student:       uuidString(studentID),
		Teacher:       uuidString(teacherID),
		Administrator: uuidString(adminID),
	}
	if image.Valid {
		resp.Image = image.String
	}
	return resp
}

func mapTeacherSignature(sig db.GetTeacherSignatureRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID)
}

func mapTeacherSignatureFromListTeacher(sig db.ListTeacherSignaturesByTeacherRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID)
}

func mapTeacherSignatureFromListTeacherCourse(sig db.ListTeacherSignaturesByTeacherAndCourseRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID)
}

func mapTeacherSignatureFromListCourse(sig db.ListTeacherSignaturesByCourseRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID)
}

func mapTeacherSignatureValues(id, courseID pgtype.UUID, signedAt pgtype.Timestamptz, status db.SignatureStatus, method db.SignatureMethod, image pgtype.Text, teacherID pgtype.UUID) teacherSignatureResponse {
	resp := teacherSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     uuidString(id),
			Date:   signedAt.Time.Unix(),
			Course: uuidString(courseID),
			Status: string(status),
			Method: string(method),
		},
		Teacher: uuidString(teacherID),
	}
	if image.Valid {
		resp.Image = image.String
	}
	return resp
}

func normalizeStatus(value string) (db.SignatureStatus, error) {
	switch value {
	case "signed", "present", "absent", "late", "excused", "invalid":
		return db.SignatureStatus(value), nil
	default:
		return "", errInvalid
	}
}

func normalizeMethod(value string) (db.SignatureMethod, error) {
	if value == "" {
		return "", errInvalid
	}
	switch value {
	case "flash":
		return db.SignatureMethod("buzzLightyear"), nil
	case "qrcode":
		return db.SignatureMethod("qrCode"), nil
	case "nfc":
		return db.SignatureMethod("nfc"), nil
	case "beacon", "buzzLightyear", "qrCode", "teacher", "web", "self", "admin":
		return db.SignatureMethod(value), nil
	default:
		return "", errInvalid
	}
}

func validateTiming(course *academicsv1.Course, signedAt time.Time) (string, string) {
	if course.GetSignatureClosed() {
		return "", "signature_closed"
	}
	start := course.GetStartAt().AsTime().UTC()
	end := course.GetEndAt().AsTime().UTC()
	if signedAt.Before(start) {
		return "", "too_early"
	}
	if signedAt.After(end) {
		return "", "course_ended"
	}
	closing := start.Add(time.Duration(course.GetSignatureClosingDelayMinutes()) * time.Minute)
	if signedAt.After(closing) {
		return "late", ""
	}
	return "", ""
}

// Identity

func (s *Server) validateStudentDevice(ctx context.Context, studentID, deviceID string) bool {
	if studentID == "" || deviceID == "" {
		return false
	}
	resp, err := s.identity.ValidateStudentDevice(ctx, &identityv1.ValidateStudentDeviceRequest{
		StudentId:        studentID,
		DeviceIdentifier: deviceID,
	})
	if err != nil {
		return false
	}
	return resp.GetIsValid()
}

func (s *Server) loadSchoolPreferences(ctx context.Context, schoolID string) (*academicsv1.SchoolPreferences, error) {
	if schoolID == "" {
		return nil, errors.New("missing school_id")
	}
	resp, err := s.academics.GetSchoolPreferences(ctx, &academicsv1.GetSchoolPreferencesRequest{SchoolId: schoolID})
	if err != nil || resp.GetPreferences() == nil {
		return nil, errors.New("preferences_not_found")
	}
	return resp.GetPreferences(), nil
}

func methodAllowedForStudent(method db.SignatureMethod, prefs *academicsv1.SchoolPreferences) bool {
	switch string(method) {
	case "buzzLightyear", "flash", "beacon":
		return prefs.GetEnableFlash()
	case "qrCode", "qrcode":
		return prefs.GetEnableQrcode()
	case "nfc":
		return prefs.GetEnableNfc()
	default:
		return true
	}
}

func parseLimit(r *http.Request, fallback int32) int32 {
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return int32(parsed)
		}
	}
	return fallback
}

func randomBuzzLightyearCode() (int32, error) {
	max := big.NewInt(1 << 28)
	value, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return int32(value.Int64()), nil
}

func (s *Server) storeBuzzLightyearCode(ctx context.Context, code int32) error {
	if s.redis == nil {
		return nil
	}
	key := fmt.Sprintf("buzzlightyear:%d", code)
	return s.redis.Set(ctx, key, "1", s.buzzTTL).Err()
}

// Utilities

var errInvalid = errors.New("invalid value")

func bearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func decodeJSON(r *http.Request, out interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func parseUUID(id string) (pgtype.UUID, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
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

func pgText(value *string) pgtype.Text {
	if value == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *value, Valid: *value != ""}
}
