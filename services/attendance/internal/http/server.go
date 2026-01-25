package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/attendance/internal/auth"
	"semaphore/attendance/internal/config"
	"semaphore/attendance/internal/db"
	identityv1 "semaphore/auth-identity/identity/v1"
)

type Server struct {
	cfg       config.Config
	store     *db.Store
	academics academicsv1.AcademicsQueryServiceClient
	identity  identityv1.IdentityQueryServiceClient
}

func NewServer(cfg config.Config, store *db.Store, academics academicsv1.AcademicsQueryServiceClient, identity identityv1.IdentityQueryServiceClient) *Server {
	return &Server{cfg: cfg, store: store, academics: academics, identity: identity}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.With(s.authMiddleware).Post("/signature", s.handleCreateSignature)
	r.With(s.authMiddleware).Get("/signature/{signatureId}", s.handleGetSignature)
	r.With(s.authMiddleware).Patch("/signature/{signatureId}", s.handlePatchSignature)
	r.With(s.authMiddleware).Delete("/signature/{signatureId}", s.handleDeleteSignature)

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
		claims, err := auth.ParseToken(s.cfg.JWTSecret, token)
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

	timingStatus, timingErr := validateTiming(course, signedAt)
	if timingErr != "" {
		writeError(w, http.StatusForbidden, timingErr)
		return
	}
	if timingStatus != "" {
		statusValue = db.SignatureStatus(timingStatus)
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
			})
		}
		return q.CreateTeacherSignature(r.Context(), db.CreateTeacherSignatureParams{
			SignatureID: pgUUID(signatureID),
			TeacherID:   pgUUIDFromString(req.Teacher),
		})
	}); err != nil {
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
	resp := studentSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     uuidString(sig.ID),
			Date:   sig.SignedAt.Time.Unix(),
			Course: uuidString(sig.CourseID),
			Status: string(sig.Status),
			Method: string(sig.Method),
		},
		Student:       uuidString(sig.StudentID),
		Teacher:       uuidString(sig.TeacherID),
		Administrator: uuidString(sig.AdministratorID),
	}
	if sig.ImageUrl.Valid {
		resp.Image = sig.ImageUrl.String
	}
	return resp
}

func mapTeacherSignature(sig db.GetTeacherSignatureRow) teacherSignatureResponse {
	resp := teacherSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     uuidString(sig.ID),
			Date:   sig.SignedAt.Time.Unix(),
			Course: uuidString(sig.CourseID),
			Status: string(sig.Status),
			Method: string(sig.Method),
		},
		Teacher: uuidString(sig.TeacherID),
	}
	if sig.ImageUrl.Valid {
		resp.Image = sig.ImageUrl.String
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
