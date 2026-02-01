package http

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"semaphore/academics/internal/auth"
	"semaphore/academics/internal/config"
	"semaphore/academics/internal/db"
	attendancev1 "semaphore/attendance/attendance/v1"
	beaconv1 "semaphore/beacon/beacon/v1"
)

type Server struct {
	cfg          config.Config
	store        *db.Store
	attendance   attendancev1.AttendanceQueryServiceClient
	beacon       beaconv1.BeaconQueryServiceClient
	jwtPublicKey *rsa.PublicKey
	httpClient   *http.Client
}

func NewServer(cfg config.Config, store *db.Store, attendance attendancev1.AttendanceQueryServiceClient, beacon beaconv1.BeaconQueryServiceClient) (*Server, error) {
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		store:        store,
		attendance:   attendance,
		beacon:       beacon,
		jwtPublicKey: publicKey,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.With(s.authMiddleware, s.requireDev).Get("/schools", s.handleGetSchools)
	r.With(s.authMiddleware, s.requireDev).Post("/school", s.handleCreateSchool)
	r.With(s.authMiddleware).Get("/school/{schoolId}", s.handleGetSchool)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/school/{schoolId}", s.handlePatchSchool)
	r.With(s.authMiddleware, s.requireDev).Delete("/school/{schoolId}", s.handleDeleteSchool)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/school/{schoolId}/preferences", s.handlePatchSchoolPreferences)

	r.With(s.authMiddleware, s.requireAdminOrDev).Get("/classrooms/{schoolId}", s.handleGetClassrooms)
	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/classroom", s.handleCreateClassroom)
	r.With(s.authMiddleware).Get("/classroom/{classroomId}", s.handleGetClassroom)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/classroom/{classroomId}", s.handlePatchClassroom)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/classroom/{classroomId}", s.handleDeleteClassroom)

	r.With(s.authMiddleware).Get("/courses", s.handleGetCourses)
	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/course", s.handleCreateCourse)
	r.With(s.authMiddleware).Get("/course/{courseId}", s.handleGetCourse)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/course/{courseId}", s.handlePatchCourse)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/course/{courseId}", s.handleDeleteCourse)

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/course/{courseId}/classrooms", s.handleAddCourseClassroom)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/course/{courseId}/classrooms/{classroomId}", s.handleRemoveCourseClassroom)

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/course/{courseId}/studentGroups", s.handleAddCourseStudentGroups)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/course/{courseId}/studentGroup/{groupId}", s.handleRemoveCourseStudentGroup)
	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/course/{courseId}/students", s.handleAddCourseStudents)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/course/{courseId}/student/{studentId}", s.handleRemoveCourseStudent)

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/course/{courseId}/teacher", s.handleAddCourseTeacher)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/course/{courseId}/teacher/{teacherId}", s.handleRemoveCourseTeacher)

	r.With(s.authMiddleware, s.requireAdminOrDev).Get("/studentGroups/{schoolId}", s.handleGetStudentGroups)
	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/studentGroup", s.handleCreateStudentGroup)
	r.With(s.authMiddleware, s.requireAdminOrDev).Get("/studentGroup/{groupId}", s.handleGetStudentGroup)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/studentGroup/{groupId}", s.handlePatchStudentGroup)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/studentGroup/{groupId}", s.handleDeleteStudentGroup)

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/studentGroup/{groupId}/students", s.handleAddStudentGroupStudents)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/studentGroup/{groupId}/student/{studentId}", s.handleRemoveStudentGroupStudent)

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

func (s *Server) requireAdminOrDev(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims == nil || (claims.UserType != "admin" && claims.UserType != "dev") {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireDev(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims == nil || claims.UserType != "dev" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ensureSchoolAccess(claims *auth.Claims, schoolID string) bool {
	if claims == nil {
		return false
	}
	if claims.UserType == "dev" {
		return true
	}
	return claims.SchoolID == schoolID
}

// Schools

type schoolPreferencesResponse struct {
	ID                              string `json:"id"`
	DefaultSignatureClosingDelay    int32  `json:"defaultSignatureClosingDelay"`
	TeacherCanModifyClosingdelay    bool   `json:"teacherCanModifyClosingdelay"`
	StudentsCanSignBeforeTeacher    bool   `json:"studentsCanSignBeforeTeacher"`
	NfcEnabled                      bool   `json:"nfcEnabled"`
	FlashlightEnabled               bool   `json:"flashlightEnabled"`
	DisableCourseModificationFromUI bool   `json:"disableCourseModificationFromUI"`
}

type schoolResponse struct {
	ID            string                     `json:"id"`
	Name          string                     `json:"name"`
	PreferencesID string                     `json:"preferencesId"`
	Preferences   *schoolPreferencesResponse `json:"preferences,omitempty"`
}

type createSchoolRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleGetSchools(w http.ResponseWriter, r *http.Request) {
	expand := r.URL.Query()["expand"]
	if len(expand) == 0 {
		expand = []string{"preferences"}
	}
	includePreferences := contains(expand, "preferences")

	schools, err := s.store.Queries.ListSchools(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]schoolResponse, 0, len(schools))
	for _, school := range schools {
		entry := schoolResponse{
			ID:            uuidString(school.ID),
			Name:          school.Name,
			PreferencesID: uuidString(school.PreferencesID),
		}
		if includePreferences {
			prefs, err := s.store.Queries.GetSchoolPreferences(r.Context(), school.PreferencesID)
			if err == nil {
				entry.Preferences = mapPreferences(prefs)
			}
		}
		resp = append(resp, entry)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateSchool(w http.ResponseWriter, r *http.Request) {
	var req createSchoolRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "missing_name")
		return
	}

	var schoolResp schoolResponse
	err := s.store.WithTx(r.Context(), func(q *db.Queries) error {
		prefsID := uuid.New()
		prefs, err := q.CreateSchoolPreferences(r.Context(), db.CreateSchoolPreferencesParams{
			ID:                                  pgUUID(prefsID),
			DefaultSignatureClosingDelayMinutes: 15,
			TeacherCanModifyClosingDelay:        true,
			StudentsCanSignBeforeTeacher:        false,
			EnableFlash:                         true,
			DisableCourseModificationFromUI:     false,
			EnableNfc:                           true,
			CreatedAt:                           nowPgTime(),
			UpdatedAt:                           nowPgTime(),
		})
		if err != nil {
			return err
		}
		schoolID := uuid.New()
		school, err := q.CreateSchool(r.Context(), db.CreateSchoolParams{
			ID:            pgUUID(schoolID),
			Name:          strings.TrimSpace(req.Name),
			PreferencesID: pgUUID(prefsID),
			CreatedAt:     nowPgTime(),
			UpdatedAt:     nowPgTime(),
		})
		if err != nil {
			return err
		}
		schoolResp = schoolResponse{
			ID:            uuidString(school.ID),
			Name:          school.Name,
			PreferencesID: uuidString(school.PreferencesID),
			Preferences:   mapPreferences(prefs),
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, schoolResp)
}

func (s *Server) handleGetSchool(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}
	if !ensureSchoolAccess(claims, schoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	expand := r.URL.Query()["expand"]
	if len(expand) == 0 {
		expand = []string{"preferences"}
	}
	includePreferences := contains(expand, "preferences")

	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	school, err := s.store.Queries.GetSchool(r.Context(), schoolUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "school_not_found")
		return
	}

	resp := schoolResponse{ID: uuidString(school.ID), Name: school.Name, PreferencesID: uuidString(school.PreferencesID)}
	if includePreferences {
		prefs, err := s.store.Queries.GetSchoolPreferences(r.Context(), school.PreferencesID)
		if err == nil {
			resp.Preferences = mapPreferences(prefs)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePatchSchool(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != schoolID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req createSchoolRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "missing_name")
		return
	}

	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	_, err = s.store.Queries.UpdateSchool(r.Context(), db.UpdateSchoolParams{
		ID:        schoolUUID,
		Name:      strings.TrimSpace(req.Name),
		UpdatedAt: nowPgTime(),
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "school_not_found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSchool(w http.ResponseWriter, r *http.Request) {
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}

	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	school, err := s.store.Queries.GetSchool(r.Context(), schoolUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "school_not_found")
		return
	}

	deletedAt := nowPgTime()
	if err := s.store.Queries.SoftDeleteSchool(r.Context(), db.SoftDeleteSchoolParams{ID: schoolUUID, DeletedAt: deletedAt}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	_ = s.store.Queries.SoftDeleteSchoolPreferences(r.Context(), db.SoftDeleteSchoolPreferencesParams{ID: school.PreferencesID, DeletedAt: deletedAt})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePatchSchoolPreferences(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != schoolID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req schoolPreferencesResponse
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	school, err := s.store.Queries.GetSchool(r.Context(), schoolUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "school_not_found")
		return
	}

	prefs, err := s.store.Queries.GetSchoolPreferences(r.Context(), school.PreferencesID)
	if err != nil {
		writeError(w, http.StatusNotFound, "preferences_not_found")
		return
	}

	updated := db.UpdateSchoolPreferencesParams{
		ID:                                  prefs.ID,
		DefaultSignatureClosingDelayMinutes: req.DefaultSignatureClosingDelay,
		TeacherCanModifyClosingDelay:        req.TeacherCanModifyClosingdelay,
		StudentsCanSignBeforeTeacher:        req.StudentsCanSignBeforeTeacher,
		EnableFlash:                         req.FlashlightEnabled,
		DisableCourseModificationFromUI:     req.DisableCourseModificationFromUI,
		EnableNfc:                           req.NfcEnabled,
		UpdatedAt:                           nowPgTime(),
	}

	// If zero-values come in, fall back to existing for booleans? The OpenAPI uses booleans, so expect full payload.
	if _, err := s.store.Queries.UpdateSchoolPreferences(r.Context(), updated); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Classrooms

type classroomResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	School string `json:"school"`
}

type createClassroomRequest struct {
	Name      string   `json:"name"`
	School    string   `json:"school"`
	BeaconsID []string `json:"beaconsId"`
}

func (s *Server) handleGetClassrooms(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}
	if !ensureSchoolAccess(claims, schoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	include := r.URL.Query()["include"]
	includeBeacons := contains(include, "beacons")

	classrooms, err := s.store.Queries.ListClassroomsBySchool(r.Context(), db.ListClassroomsBySchoolParams{SchoolID: schoolUUID, Limit: 200})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]any, 0, len(classrooms))
	for _, room := range classrooms {
		if includeBeacons {
			entry := mapClassroomBase(room)
			beacons, err := s.listClassroomBeacons(r.Context(), room.ID)
			if err != nil {
				writeError(w, http.StatusBadGateway, "beacon_lookup_failed")
				return
			}
			entry["beacons"] = beacons
			resp = append(resp, entry)
			continue
		}
		resp = append(resp, classroomResponse{ID: uuidString(room.ID), Name: room.Name, School: uuidString(room.SchoolID)})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateClassroom(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	var req createClassroomRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "missing_name")
		return
	}
	if req.School == "" && claims != nil && claims.UserType == "admin" {
		req.School = claims.SchoolID
	}
	if strings.TrimSpace(req.School) == "" {
		writeError(w, http.StatusBadRequest, "missing_school")
		return
	}
	for _, beaconID := range req.BeaconsID {
		if _, err := parseUUID(beaconID); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_beacon_id")
			return
		}
	}

	schoolUUID, err := parseUUID(req.School)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	room, err := s.store.Queries.CreateClassroom(r.Context(), db.CreateClassroomParams{
		ID:        pgUUID(uuid.New()),
		SchoolID:  schoolUUID,
		Name:      strings.TrimSpace(req.Name),
		CreatedAt: nowPgTime(),
		UpdatedAt: nowPgTime(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if len(req.BeaconsID) > 0 {
		authHeader := r.Header.Get("Authorization")
		classroomID := uuidString(room.ID)
		assigned := make([]string, 0, len(req.BeaconsID))
		for _, beaconID := range req.BeaconsID {
			if err := s.assignBeaconToClassroom(r.Context(), authHeader, beaconID, classroomID); err != nil {
				for _, assignedID := range assigned {
					_ = s.removeBeaconFromClassroom(r.Context(), authHeader, assignedID, classroomID)
				}
				_ = s.store.Queries.SoftDeleteClassroom(r.Context(), db.SoftDeleteClassroomParams{
					ID:        room.ID,
					DeletedAt: nowPgTime(),
				})
				var beaconErr *beaconRequestError
				if errors.As(err, &beaconErr) {
					writeError(w, beaconErr.status, beaconErr.code)
					return
				}
				writeError(w, http.StatusBadGateway, "beacon_assignment_failed")
				return
			}
			assigned = append(assigned, beaconID)
		}
	}

	writeJSON(w, http.StatusOK, classroomResponse{ID: uuidString(room.ID), Name: room.Name, School: uuidString(room.SchoolID)})
}

func (s *Server) handleGetClassroom(w http.ResponseWriter, r *http.Request) {
	classroomID := chi.URLParam(r, "classroomId")
	if classroomID == "" {
		writeError(w, http.StatusBadRequest, "missing_classroom_id")
		return
	}

	classroomUUID, err := parseUUID(classroomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}

	room, err := s.store.Queries.GetClassroom(r.Context(), classroomUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "classroom_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType != "dev" && claims.SchoolID != uuidString(room.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	include := r.URL.Query()["include"]
	includeBeacons := contains(include, "beacons")
	if includeBeacons {
		entry := mapClassroomBase(room)
		beacons, err := s.listClassroomBeacons(r.Context(), room.ID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "beacon_lookup_failed")
			return
		}
		entry["beacons"] = beacons
		writeJSON(w, http.StatusOK, entry)
		return
	}

	writeJSON(w, http.StatusOK, classroomResponse{ID: uuidString(room.ID), Name: room.Name, School: uuidString(room.SchoolID)})
}

func (s *Server) handlePatchClassroom(w http.ResponseWriter, r *http.Request) {
	classroomID := chi.URLParam(r, "classroomId")
	if classroomID == "" {
		writeError(w, http.StatusBadRequest, "missing_classroom_id")
		return
	}
	var req createClassroomRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "missing_name")
		return
	}

	classroomUUID, err := parseUUID(classroomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}

	current, err := s.store.Queries.GetClassroom(r.Context(), classroomUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "classroom_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(current.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	room, err := s.store.Queries.UpdateClassroom(r.Context(), db.UpdateClassroomParams{
		ID:        classroomUUID,
		Name:      strings.TrimSpace(req.Name),
		UpdatedAt: nowPgTime(),
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "classroom_not_found")
		return
	}

	writeJSON(w, http.StatusOK, classroomResponse{ID: uuidString(room.ID), Name: room.Name, School: uuidString(room.SchoolID)})
}

func (s *Server) handleDeleteClassroom(w http.ResponseWriter, r *http.Request) {
	classroomID := chi.URLParam(r, "classroomId")
	if classroomID == "" {
		writeError(w, http.StatusBadRequest, "missing_classroom_id")
		return
	}

	classroomUUID, err := parseUUID(classroomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}
	current, err := s.store.Queries.GetClassroom(r.Context(), classroomUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "classroom_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(current.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := s.store.Queries.SoftDeleteClassroom(r.Context(), db.SoftDeleteClassroomParams{ID: classroomUUID, DeletedAt: nowPgTime()}); err != nil {
		writeError(w, http.StatusNotFound, "classroom_not_found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Courses

type courseResponse struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	Date                  int64  `json:"date"`
	EndDate               int64  `json:"endDate"`
	IsOnline              bool   `json:"isOnline"`
	SignatureClosingDelay int32  `json:"signatureClosingDelay"`
	SignatureClosed       bool   `json:"signatureClosed"`
	School                string `json:"school"`
}

type createCourseRequest struct {
	Name            string   `json:"name"`
	Date            int64    `json:"date"`
	EndDate         int64    `json:"endDate"`
	IsOnline        bool     `json:"isOnline"`
	School          string   `json:"school"`
	ClassroomsID    []string `json:"classroomsId,omitempty"`
	TeachersID      []string `json:"teachersId,omitempty"`
	StudentsID      []string `json:"studentsId,omitempty"`
	StudentGroupsID []string `json:"studentGroupsId,omitempty"`
}

type patchCourseRequest struct {
	Name                  *string `json:"name"`
	Date                  *int64  `json:"date"`
	EndDate               *int64  `json:"endDate"`
	IsOnline              *bool   `json:"isOnline"`
	SignatureClosingDelay *int32  `json:"signatureClosingDelay"`
	SignatureClosed       *bool   `json:"signatureClosed"`
}

func (s *Server) handleGetCourses(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	userID := r.URL.Query().Get("userId")
	isAdminDev := claims.UserType == "admin" || claims.UserType == "dev"
	if userID != "" && !isAdminDev {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	include := r.URL.Query()["include"]
	if len(include) == 0 {
		include = []string{"classrooms", "signatures", "students", "soloStudents", "studentGroups"}
	}
	includeClassrooms := contains(include, "classrooms")
	includeSignatures := contains(include, "signatures")
	includeStudents := contains(include, "students")
	includeSoloStudents := contains(include, "soloStudents")
	includeStudentGroups := contains(include, "studentGroups")

	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	var fromDate, toDate *time.Time
	if from := r.URL.Query().Get("from"); from != "" {
		if parsed, err := time.Parse("2006-01-02", from); err == nil {
			fromDate = &parsed
		}
	}
	if to := r.URL.Query().Get("to"); to != "" {
		if parsed, err := time.Parse("2006-01-02", to); err == nil {
			toDate = &parsed
		}
	}

	if fromDate == nil && toDate == nil {
		rangeDays := s.cfg.CourseDefaultRangeDays
		if rangeDays <= 0 {
			rangeDays = 10
		}
		now := time.Now().UTC()
		anchor := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		start := anchor.AddDate(0, 0, -rangeDays)
		end := anchor.AddDate(0, 0, rangeDays)
		fromDate = &start
		toDate = &end
	}

	var courses []db.Course
	var err error
	if userID == "" && isAdminDev {
		courses, err = s.listCoursesForSchool(r.Context(), claims.SchoolID, limit, fromDate, toDate)
	} else {
		if userID == "" {
			userID = claims.UserID
		}
		courses, err = s.listCoursesForUser(r.Context(), claims, userID, limit, fromDate, toDate)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]any, 0, len(courses))
	for _, course := range courses {
		if !includeClassrooms && !includeSignatures && !includeStudents && !includeSoloStudents && !includeStudentGroups {
			resp = append(resp, mapCourse(course))
			continue
		}
		entry, err := s.buildCourseEntry(r.Context(), course, courseIncludes{
			Classrooms:    includeClassrooms,
			Signatures:    includeSignatures,
			Students:      includeStudents,
			SoloStudents:  includeSoloStudents,
			StudentGroups: includeStudentGroups,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		resp = append(resp, entry)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) listCoursesForUser(ctx context.Context, claims *auth.Claims, userID string, limit int, fromDate, toDate *time.Time) ([]db.Course, error) {
	userUUID, err := parseUUID(userID)
	if err != nil {
		return nil, err
	}

	isAdminDev := claims.UserType == "admin" || claims.UserType == "dev"
	if fromDate != nil && toDate != nil {
		if isAdminDev {
			teacherCourses, err := s.store.Queries.ListCoursesByTeacherWithinRange(ctx, db.ListCoursesByTeacherWithinRangeParams{
				TeacherID: userUUID,
				StartAt:   pgTime(fromDate.UTC()),
				StartAt_2: pgTime(toDate.UTC()),
				Limit:     int32(limit),
			})
			if err == nil && len(teacherCourses) > 0 {
				return teacherCourses, nil
			}
			studentCourses, err := s.store.Queries.ListCoursesByStudentWithinRange(ctx, db.ListCoursesByStudentWithinRangeParams{
				StudentID: userUUID,
				StartAt:   pgTime(fromDate.UTC()),
				StartAt_2: pgTime(toDate.UTC()),
				Limit:     int32(limit),
			})
			return studentCourses, err
		}
		if claims.UserType == "teacher" {
			return s.store.Queries.ListCoursesByTeacherWithinRange(ctx, db.ListCoursesByTeacherWithinRangeParams{
				TeacherID: userUUID,
				StartAt:   pgTime(fromDate.UTC()),
				StartAt_2: pgTime(toDate.UTC()),
				Limit:     int32(limit),
			})
		}
		if claims.UserType == "student" {
			return s.store.Queries.ListCoursesByStudentWithinRange(ctx, db.ListCoursesByStudentWithinRangeParams{
				StudentID: userUUID,
				StartAt:   pgTime(fromDate.UTC()),
				StartAt_2: pgTime(toDate.UTC()),
				Limit:     int32(limit),
			})
		}
		return s.store.Queries.ListCoursesBySchoolWithinRange(ctx, db.ListCoursesBySchoolWithinRangeParams{
			SchoolID:  pgUUIDFromString(claims.SchoolID),
			StartAt:   pgTime(fromDate.UTC()),
			StartAt_2: pgTime(toDate.UTC()),
			Limit:     int32(limit),
		})
	}

	if claims.UserType == "teacher" {
		return s.store.Queries.ListCoursesByTeacher(ctx, db.ListCoursesByTeacherParams{TeacherID: userUUID, Limit: int32(limit)})
	}
	if claims.UserType == "student" {
		return s.store.Queries.ListCoursesByStudent(ctx, db.ListCoursesByStudentParams{StudentID: userUUID, Limit: int32(limit)})
	}
	if isAdminDev {
		teacherCourses, err := s.store.Queries.ListCoursesByTeacher(ctx, db.ListCoursesByTeacherParams{TeacherID: userUUID, Limit: int32(limit)})
		if err == nil && len(teacherCourses) > 0 {
			return teacherCourses, nil
		}
		studentCourses, err := s.store.Queries.ListCoursesByStudent(ctx, db.ListCoursesByStudentParams{StudentID: userUUID, Limit: int32(limit)})
		return studentCourses, err
	}
	return s.store.Queries.ListCoursesBySchool(ctx, db.ListCoursesBySchoolParams{SchoolID: pgUUIDFromString(claims.SchoolID), Limit: int32(limit)})
}

func (s *Server) listCoursesForSchool(ctx context.Context, schoolID string, limit int, fromDate, toDate *time.Time) ([]db.Course, error) {
	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		return nil, err
	}
	if fromDate != nil && toDate != nil {
		return s.store.Queries.ListCoursesBySchoolWithinRange(ctx, db.ListCoursesBySchoolWithinRangeParams{
			SchoolID:  schoolUUID,
			StartAt:   pgTime(fromDate.UTC()),
			StartAt_2: pgTime(toDate.UTC()),
			Limit:     int32(limit),
		})
	}
	return s.store.Queries.ListCoursesBySchool(ctx, db.ListCoursesBySchoolParams{SchoolID: schoolUUID, Limit: int32(limit)})
}

type courseIncludes struct {
	Classrooms    bool
	Signatures    bool
	Students      bool
	SoloStudents  bool
	StudentGroups bool
}

func (s *Server) buildCourseEntry(ctx context.Context, course db.Course, includes courseIncludes) (map[string]interface{}, error) {
	entry := mapCourseBase(course)
	if includes.Classrooms {
		classrooms, err := s.store.Queries.ListClassroomsByCourse(ctx, course.ID)
		if err != nil {
			return nil, err
		}
		entry["classrooms"] = mapClassroomResponses(classrooms)
	}
	if includes.Signatures {
		signatures, err := s.listCourseSignatures(ctx, course.ID)
		if err != nil {
			return nil, err
		}
		entry["signature"] = signatures
	}
	if includes.Students || includes.SoloStudents || includes.StudentGroups {
		groups, students, soloStudents, err := s.listCourseStudents(ctx, course.ID)
		if err != nil {
			return nil, err
		}
		if includes.StudentGroups {
			entry["studentGroups"] = mapStudentGroupResponses(groups)
		}
		if includes.Students {
			entry["students"] = mapStudentRefStrings(students)
		}
		if includes.SoloStudents {
			entry["soloStudents"] = mapStudentRefStrings(soloStudents)
		}
	}
	return entry, nil
}

func (s *Server) listCourseSignatures(ctx context.Context, courseID pgtype.UUID) ([]any, error) {
	if s.attendance == nil {
		return nil, errors.New("attendance client not configured")
	}

	resp, err := s.attendance.ListCourseSignatures(ctx, &attendancev1.ListCourseSignaturesRequest{CourseId: uuidString(courseID)})
	if err != nil {
		return nil, err
	}

	items := make([]any, 0, len(resp.GetStudentSignatures())+len(resp.GetTeacherSignatures()))
	for _, sig := range resp.GetStudentSignatures() {
		items = append(items, mapStudentSignatureFromGRPC(sig))
	}
	for _, sig := range resp.GetTeacherSignatures() {
		items = append(items, mapTeacherSignatureFromGRPC(sig))
	}
	return items, nil
}

func (s *Server) listClassroomBeacons(ctx context.Context, classroomID pgtype.UUID) ([]any, error) {
	if s.beacon == nil {
		return nil, errors.New("beacon client not configured")
	}

	resp, err := s.beacon.ListBeaconsByClassroom(ctx, &beaconv1.ListBeaconsByClassroomRequest{ClassroomId: uuidString(classroomID)})
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(resp.GetBeacons()))
	for _, beacon := range resp.GetBeacons() {
		items = append(items, mapBeaconFromGRPC(beacon))
	}
	return items, nil
}

func (s *Server) listCourseStudents(ctx context.Context, courseID pgtype.UUID) ([]db.StudentGroup, []string, []string, error) {
	groups, err := s.store.Queries.ListStudentGroupsByCourse(ctx, courseID)
	if err != nil {
		return nil, nil, nil, err
	}

	all := make([]string, 0)
	solo := make([]string, 0)
	allSet := make(map[string]struct{})
	soloSet := make(map[string]struct{})

	for _, group := range groups {
		studentIDs, err := s.store.Queries.ListStudentIDsByStudentGroup(ctx, group.ID)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, id := range studentIDs {
			idStr := uuidString(id)
			if _, exists := allSet[idStr]; !exists {
				allSet[idStr] = struct{}{}
				all = append(all, idStr)
			}
			if group.SingleStudentGroup {
				if _, exists := soloSet[idStr]; !exists {
					soloSet[idStr] = struct{}{}
					solo = append(solo, idStr)
				}
			}
		}
	}

	return groups, all, solo, nil
}

func (s *Server) addSingleStudentsToCourse(ctx context.Context, q *db.Queries, course db.Course, studentIDs []pgtype.UUID) error {
	for _, studentID := range studentIDs {
		matchedGroups, err := q.ListMatchedStudentCourseGroups(ctx, db.ListMatchedStudentCourseGroupsParams{
			StudentID: studentID,
			CourseID:  course.ID,
		})
		if err != nil {
			return err
		}
		if len(matchedGroups) > 0 {
			continue
		}
		group, err := q.CreateStudentGroup(ctx, db.CreateStudentGroupParams{
			ID:                 pgUUID(uuid.New()),
			SchoolID:           course.SchoolID,
			Name:               "single-" + uuidString(studentID),
			SingleStudentGroup: true,
			CreatedAt:          nowPgTime(),
			UpdatedAt:          nowPgTime(),
		})
		if err != nil {
			return err
		}
		if err := q.AddStudentGroupMembers(ctx, db.AddStudentGroupMembersParams{
			ID:             pgUUID(uuid.New()),
			StudentID:      studentID,
			StudentGroupID: group.ID,
			CreatedAt:      nowPgTime(),
		}); err != nil {
			return err
		}
		if err := q.AddCourseStudentGroup(ctx, db.AddCourseStudentGroupParams{
			ID:             pgUUID(uuid.New()),
			CourseID:       course.ID,
			StudentGroupID: group.ID,
			CreatedAt:      nowPgTime(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleCreateCourse(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	var req createCourseRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.Name == "" || req.Date == 0 || req.EndDate == 0 {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if claims != nil && claims.UserType != "dev" {
		req.School = claims.SchoolID
	} else if req.School == "" && claims != nil && claims.SchoolID != "" {
		req.School = claims.SchoolID
	}
	if req.School == "" {
		writeError(w, http.StatusBadRequest, "missing_school")
		return
	}

	schoolUUID, err := parseUUID(req.School)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school")
		return
	}

	// load school preferences for default closing delay
	school, err := s.store.Queries.GetSchool(r.Context(), schoolUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "school_not_found")
		return
	}
	prefs, err := s.store.Queries.GetSchoolPreferences(r.Context(), school.PreferencesID)
	if err != nil {
		writeError(w, http.StatusNotFound, "preferences_not_found")
		return
	}

	classroomUUIDs := make([]pgtype.UUID, 0, len(req.ClassroomsID))
	for _, classroomID := range req.ClassroomsID {
		classroomUUID, err := parseUUID(classroomID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_classroom_id")
			return
		}
		classroomUUIDs = append(classroomUUIDs, classroomUUID)
	}

	teacherUUIDs := make([]pgtype.UUID, 0, len(req.TeachersID))
	for _, teacherID := range req.TeachersID {
		teacherUUID, err := parseUUID(teacherID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_teacher_id")
			return
		}
		teacherUUIDs = append(teacherUUIDs, teacherUUID)
	}

	studentGroupUUIDs := make([]pgtype.UUID, 0, len(req.StudentGroupsID))
	for _, groupID := range req.StudentGroupsID {
		groupUUID, err := parseUUID(groupID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_group_id")
			return
		}
		studentGroupUUIDs = append(studentGroupUUIDs, groupUUID)
	}

	studentUUIDs := make([]pgtype.UUID, 0, len(req.StudentsID))
	for _, studentID := range req.StudentsID {
		studentUUID, err := parseUUID(studentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_student_id")
			return
		}
		studentUUIDs = append(studentUUIDs, studentUUID)
	}

	startAt := time.Unix(req.Date, 0).UTC()
	endAt := time.Unix(req.EndDate, 0).UTC()

	var course db.Course
	err = s.store.WithTx(r.Context(), func(q *db.Queries) error {
		var err error
		course, err = q.CreateCourse(r.Context(), db.CreateCourseParams{
			ID:                           pgUUID(uuid.New()),
			SchoolID:                     schoolUUID,
			Name:                         req.Name,
			StartAt:                      pgTime(startAt),
			EndAt:                        pgTime(endAt),
			IsOnline:                     req.IsOnline,
			SignatureClosingDelayMinutes: prefs.DefaultSignatureClosingDelayMinutes,
			SignatureClosed:              false,
			CreatedAt:                    nowPgTime(),
			UpdatedAt:                    nowPgTime(),
		})
		if err != nil {
			return err
		}

		for _, classroomUUID := range classroomUUIDs {
			if err := q.AddCourseClassroom(r.Context(), db.AddCourseClassroomParams{
				ID:          pgUUID(uuid.New()),
				CourseID:    course.ID,
				ClassroomID: classroomUUID,
				CreatedAt:   nowPgTime(),
			}); err != nil {
				return err
			}
		}

		for _, teacherUUID := range teacherUUIDs {
			if err := q.AddCourseTeacher(r.Context(), db.AddCourseTeacherParams{
				ID:        pgUUID(uuid.New()),
				TeacherID: teacherUUID,
				CourseID:  course.ID,
				CreatedAt: nowPgTime(),
			}); err != nil {
				return err
			}
		}

		for _, groupUUID := range studentGroupUUIDs {
			if err := q.AddCourseStudentGroup(r.Context(), db.AddCourseStudentGroupParams{
				ID:             pgUUID(uuid.New()),
				CourseID:       course.ID,
				StudentGroupID: groupUUID,
				CreatedAt:      nowPgTime(),
			}); err != nil {
				return err
			}
		}

		if len(studentUUIDs) > 0 {
			if err := s.addSingleStudentsToCourse(r.Context(), q, course, studentUUIDs); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, mapCourse(course))
}

func (s *Server) handleGetCourse(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	courseID := chi.URLParam(r, "courseId")
	if courseID == "" {
		writeError(w, http.StatusBadRequest, "missing_course_id")
		return
	}

	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}

	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if claims != nil && (claims.UserType == "student" || claims.UserType == "teacher") {
		if claims.UserType == "student" {
			allowed, _ := s.store.Queries.ValidateStudentCourse(r.Context(), db.ValidateStudentCourseParams{
				StudentID: pgUUIDFromString(claims.UserID),
				CourseID:  courseUUID,
			})
			if !allowed {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
		} else if claims.UserType == "teacher" {
			assigned, _ := s.store.Queries.ValidateTeacherCourse(r.Context(), db.ValidateTeacherCourseParams{
				TeacherID: pgUUIDFromString(claims.UserID),
				CourseID:  courseUUID,
			})
			if !assigned {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}

	include := r.URL.Query()["include"]
	if len(include) == 0 {
		include = []string{"classrooms", "signatures", "students", "soloStudents", "studentGroups"}
	}
	includeClassrooms := contains(include, "classrooms")
	includeSignatures := contains(include, "signatures")
	includeStudents := contains(include, "students")
	includeSoloStudents := contains(include, "soloStudents")
	includeStudentGroups := contains(include, "studentGroups")
	if !includeClassrooms && !includeSignatures && !includeStudents && !includeSoloStudents && !includeStudentGroups {
		writeJSON(w, http.StatusOK, mapCourse(course))
		return
	}
	entry, err := s.buildCourseEntry(r.Context(), course, courseIncludes{
		Classrooms:    includeClassrooms,
		Signatures:    includeSignatures,
		Students:      includeStudents,
		SoloStudents:  includeSoloStudents,
		StudentGroups: includeStudentGroups,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) handlePatchCourse(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	if courseID == "" {
		writeError(w, http.StatusBadRequest, "missing_course_id")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}

	var req patchCourseRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	name := course.Name
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			writeError(w, http.StatusBadRequest, "missing_name")
			return
		}
		name = trimmed
	}
	startAt := course.StartAt.Time
	endAt := course.EndAt.Time
	if req.Date != nil {
		if *req.Date == 0 {
			writeError(w, http.StatusBadRequest, "missing_date")
			return
		}
		startAt = time.Unix(*req.Date, 0).UTC()
		if req.EndDate == nil || *req.EndDate == 0 {
			writeError(w, http.StatusBadRequest, "missing_end_date")
			return
		}
		endAt = time.Unix(*req.EndDate, 0).UTC()
	} else if req.EndDate != nil {
		if *req.EndDate == 0 {
			writeError(w, http.StatusBadRequest, "missing_end_date")
			return
		}
		endAt = time.Unix(*req.EndDate, 0).UTC()
	}
	isOnline := course.IsOnline
	if req.IsOnline != nil {
		isOnline = *req.IsOnline
	}
	signatureClosingDelay := course.SignatureClosingDelayMinutes
	if req.SignatureClosingDelay != nil {
		signatureClosingDelay = *req.SignatureClosingDelay
	}
	signatureClosed := course.SignatureClosed
	if req.SignatureClosed != nil {
		signatureClosed = *req.SignatureClosed
	}

	updated, err := s.store.Queries.UpdateCourse(r.Context(), db.UpdateCourseParams{
		ID:                           courseUUID,
		Name:                         name,
		StartAt:                      pgTime(startAt),
		EndAt:                        pgTime(endAt),
		IsOnline:                     isOnline,
		SignatureClosingDelayMinutes: signatureClosingDelay,
		SignatureClosed:              signatureClosed,
		UpdatedAt:                    nowPgTime(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, mapCourse(updated))
}

func (s *Server) handleDeleteCourse(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	if courseID == "" {
		writeError(w, http.StatusBadRequest, "missing_course_id")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.store.Queries.SoftDeleteCourse(r.Context(), db.SoftDeleteCourseParams{ID: courseUUID, DeletedAt: nowPgTime()}); err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddCourseClassroom(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	var req struct {
		ClassroomID string `json:"classroomId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	classroomUUID, err := parseUUID(req.ClassroomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}
	if err := s.store.Queries.AddCourseClassroom(r.Context(), db.AddCourseClassroomParams{
		ID:          pgUUID(uuid.New()),
		CourseID:    courseUUID,
		ClassroomID: classroomUUID,
		CreatedAt:   nowPgTime(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveCourseClassroom(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	classroomID := chi.URLParam(r, "classroomId")
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	classroomUUID, err := parseUUID(classroomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}
	if err := s.store.Queries.RemoveCourseClassroom(r.Context(), db.RemoveCourseClassroomParams{CourseID: courseUUID, ClassroomID: classroomUUID}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddCourseStudentGroups(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	var req struct {
		GroupsIds []string `json:"groupsIds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	for _, groupID := range req.GroupsIds {
		groupUUID, err := parseUUID(groupID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_group_id")
			return
		}
		if err := s.store.Queries.AddCourseStudentGroup(r.Context(), db.AddCourseStudentGroupParams{
			ID:             pgUUID(uuid.New()),
			CourseID:       courseUUID,
			StudentGroupID: groupUUID,
			CreatedAt:      nowPgTime(),
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveCourseStudentGroup(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	groupID := chi.URLParam(r, "groupId")
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	groupUUID, err := parseUUID(groupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group_id")
		return
	}
	if err := s.store.Queries.RemoveCourseStudentGroup(r.Context(), db.RemoveCourseStudentGroupParams{CourseID: courseUUID, StudentGroupID: groupUUID}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddCourseStudents(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	var req struct {
		StudentsID []string `json:"studentsId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.StudentsID) == 0 {
		writeError(w, http.StatusBadRequest, "missing_students")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	studentUUIDs := make([]pgtype.UUID, 0, len(req.StudentsID))
	for _, studentID := range req.StudentsID {
		studentUUID, err := parseUUID(studentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_student_id")
			return
		}
		studentUUIDs = append(studentUUIDs, studentUUID)
	}

	if err := s.store.WithTx(r.Context(), func(q *db.Queries) error {
		return s.addSingleStudentsToCourse(r.Context(), q, course, studentUUIDs)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveCourseStudent(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	studentID := chi.URLParam(r, "studentId")
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	studentUUID, err := parseUUID(studentID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_student_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := s.store.WithTx(r.Context(), func(q *db.Queries) error {
		matchedGroups, err := q.ListMatchedStudentCourseGroups(r.Context(), db.ListMatchedStudentCourseGroupsParams{
			StudentID: studentUUID,
			CourseID:  courseUUID,
		})
		if err != nil {
			return err
		}
		if len(matchedGroups) == 0 {
			return pgx.ErrNoRows
		}
		for _, groupID := range matchedGroups {
			group, err := q.GetStudentGroup(r.Context(), groupID)
			if err != nil {
				return err
			}
			if !group.SingleStudentGroup {
				continue
			}
			if err := q.RemoveCourseStudentGroup(r.Context(), db.RemoveCourseStudentGroupParams{
				CourseID:       courseUUID,
				StudentGroupID: groupID,
			}); err != nil {
				return err
			}
			if err := q.RemoveStudentGroupMember(r.Context(), db.RemoveStudentGroupMemberParams{
				StudentGroupID: groupID,
				StudentID:      studentUUID,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "student_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddCourseTeacher(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	var req struct {
		TeacherID string `json:"teacherId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	teacherUUID, err := parseUUID(req.TeacherID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_teacher_id")
		return
	}
	if err := s.store.Queries.AddCourseTeacher(r.Context(), db.AddCourseTeacherParams{
		ID:        pgUUID(uuid.New()),
		TeacherID: teacherUUID,
		CourseID:  courseUUID,
		CreatedAt: nowPgTime(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveCourseTeacher(w http.ResponseWriter, r *http.Request) {
	courseID := chi.URLParam(r, "courseId")
	teacherID := chi.URLParam(r, "teacherId")
	courseUUID, err := parseUUID(courseID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}
	course, err := s.store.Queries.GetCourse(r.Context(), courseUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(course.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	teacherUUID, err := parseUUID(teacherID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_teacher_id")
		return
	}
	if err := s.store.Queries.RemoveCourseTeacher(r.Context(), db.RemoveCourseTeacherParams{TeacherID: teacherUUID, CourseID: courseUUID}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Student groups

type studentGroupResponse struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	SingleStudentGroup bool   `json:"singleStudentGroup"`
	School             string `json:"school"`
}

type createStudentGroupRequest struct {
	Name               string `json:"name"`
	SingleStudentGroup bool   `json:"singleStudentGroup"`
	School             string `json:"school"`
}

func (s *Server) handleGetStudentGroups(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}
	if !ensureSchoolAccess(claims, schoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	schoolUUID, err := parseUUID(schoolID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	include := r.URL.Query()["include"]
	if len(include) == 0 {
		include = []string{"courses"}
	}
	includeCourses := contains(include, "courses")
	includeStudents := contains(include, "students")

	groups, err := s.store.Queries.ListStudentGroupsBySchool(r.Context(), db.ListStudentGroupsBySchoolParams{SchoolID: schoolUUID, Limit: 200})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]any, 0, len(groups))
	for _, group := range groups {
		if !includeCourses && !includeStudents {
			resp = append(resp, studentGroupResponse{
				ID:                 uuidString(group.ID),
				Name:               group.Name,
				SingleStudentGroup: group.SingleStudentGroup,
				School:             uuidString(group.SchoolID),
			})
			continue
		}
		entry := mapStudentGroupBase(group)
		if includeCourses {
			courses, err := s.store.Queries.ListCoursesByStudentGroup(r.Context(), group.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			entry["courses"] = mapCourseResponses(courses)
		}
		if includeStudents {
			students, err := s.store.Queries.ListStudentIDsByStudentGroup(r.Context(), group.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			entry["students"] = mapStudentRefs(students)
		}
		resp = append(resp, entry)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateStudentGroup(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	var req createStudentGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "missing_name")
		return
	}
	if req.School == "" && claims != nil && claims.UserType == "admin" {
		req.School = claims.SchoolID
	}
	if req.School == "" {
		writeError(w, http.StatusBadRequest, "missing_school")
		return
	}

	schoolUUID, err := parseUUID(req.School)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_school_id")
		return
	}

	group, err := s.store.Queries.CreateStudentGroup(r.Context(), db.CreateStudentGroupParams{
		ID:                 pgUUID(uuid.New()),
		SchoolID:           schoolUUID,
		Name:               strings.TrimSpace(req.Name),
		SingleStudentGroup: req.SingleStudentGroup,
		CreatedAt:          nowPgTime(),
		UpdatedAt:          nowPgTime(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, studentGroupResponse{
		ID:                 uuidString(group.ID),
		Name:               group.Name,
		SingleStudentGroup: group.SingleStudentGroup,
		School:             uuidString(group.SchoolID),
	})
}

func (s *Server) handleGetStudentGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	groupUUID, err := parseUUID(groupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group_id")
		return
	}

	group, err := s.store.Queries.GetStudentGroup(r.Context(), groupUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "group_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(group.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	include := r.URL.Query()["include"]
	if len(include) == 0 {
		include = []string{"courses"}
	}
	includeCourses := contains(include, "courses")
	includeStudents := contains(include, "students")
	if !includeCourses && !includeStudents {
		writeJSON(w, http.StatusOK, studentGroupResponse{
			ID:                 uuidString(group.ID),
			Name:               group.Name,
			SingleStudentGroup: group.SingleStudentGroup,
			School:             uuidString(group.SchoolID),
		})
		return
	}
	entry := mapStudentGroupBase(group)
	if includeCourses {
		courses, err := s.store.Queries.ListCoursesByStudentGroup(r.Context(), group.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		entry["courses"] = mapCourseResponses(courses)
	}
	if includeStudents {
		students, err := s.store.Queries.ListStudentIDsByStudentGroup(r.Context(), group.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		entry["students"] = mapStudentRefs(students)
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) handlePatchStudentGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	groupUUID, err := parseUUID(groupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group_id")
		return
	}

	var req createStudentGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "missing_name")
		return
	}

	current, err := s.store.Queries.GetStudentGroup(r.Context(), groupUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "group_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(current.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	group, err := s.store.Queries.UpdateStudentGroup(r.Context(), db.UpdateStudentGroupParams{
		ID:                 groupUUID,
		Name:               strings.TrimSpace(req.Name),
		SingleStudentGroup: req.SingleStudentGroup,
		UpdatedAt:          nowPgTime(),
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "group_not_found")
		return
	}

	writeJSON(w, http.StatusOK, studentGroupResponse{
		ID:                 uuidString(group.ID),
		Name:               group.Name,
		SingleStudentGroup: group.SingleStudentGroup,
		School:             uuidString(group.SchoolID),
	})
}

func (s *Server) handleDeleteStudentGroup(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	groupUUID, err := parseUUID(groupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group_id")
		return
	}
	current, err := s.store.Queries.GetStudentGroup(r.Context(), groupUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "group_not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims != nil && claims.UserType == "admin" && claims.SchoolID != uuidString(current.SchoolID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.store.Queries.SoftDeleteStudentGroup(r.Context(), db.SoftDeleteStudentGroupParams{ID: groupUUID, DeletedAt: nowPgTime()}); err != nil {
		writeError(w, http.StatusNotFound, "group_not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddStudentGroupStudents(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		writeError(w, http.StatusBadRequest, "missing_group_id")
		return
	}
	var req struct {
		StudentsIds []string `json:"studentsIds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	groupUUID, err := parseUUID(groupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group_id")
		return
	}
	for _, studentID := range req.StudentsIds {
		studentUUID, err := parseUUID(studentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_student_id")
			return
		}
		if err := s.store.Queries.AddStudentGroupMembers(r.Context(), db.AddStudentGroupMembersParams{
			ID:             pgUUID(uuid.New()),
			StudentID:      studentUUID,
			StudentGroupID: groupUUID,
			CreatedAt:      nowPgTime(),
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveStudentGroupStudent(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupId")
	studentID := chi.URLParam(r, "studentId")
	groupUUID, err := parseUUID(groupID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_group_id")
		return
	}
	studentUUID, err := parseUUID(studentID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_student_id")
		return
	}
	if err := s.store.Queries.RemoveStudentGroupMember(r.Context(), db.RemoveStudentGroupMemberParams{StudentGroupID: groupUUID, StudentID: studentUUID}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// helpers

func mapPreferences(prefs db.SchoolPreference) *schoolPreferencesResponse {
	return &schoolPreferencesResponse{
		ID:                              uuidString(prefs.ID),
		DefaultSignatureClosingDelay:    prefs.DefaultSignatureClosingDelayMinutes,
		TeacherCanModifyClosingdelay:    prefs.TeacherCanModifyClosingDelay,
		StudentsCanSignBeforeTeacher:    prefs.StudentsCanSignBeforeTeacher,
		NfcEnabled:                      prefs.EnableNfc,
		FlashlightEnabled:               prefs.EnableFlash,
		DisableCourseModificationFromUI: prefs.DisableCourseModificationFromUI,
	}
}

func mapCourse(course db.Course) courseResponse {
	return courseResponse{
		ID:                    uuidString(course.ID),
		Name:                  course.Name,
		Date:                  course.StartAt.Time.Unix(),
		EndDate:               course.EndAt.Time.Unix(),
		IsOnline:              course.IsOnline,
		SignatureClosingDelay: course.SignatureClosingDelayMinutes,
		SignatureClosed:       course.SignatureClosed,
		School:                uuidString(course.SchoolID),
	}
}

type studentRef struct {
	ID string `json:"id"`
}

func mapClassroomResponses(classrooms []db.Classroom) []classroomResponse {
	resp := make([]classroomResponse, 0, len(classrooms))
	for _, room := range classrooms {
		resp = append(resp, classroomResponse{
			ID:     uuidString(room.ID),
			Name:   room.Name,
			School: uuidString(room.SchoolID),
		})
	}
	return resp
}

func mapCourseResponses(courses []db.Course) []courseResponse {
	resp := make([]courseResponse, 0, len(courses))
	for _, course := range courses {
		resp = append(resp, mapCourse(course))
	}
	return resp
}

func mapStudentRefs(ids []pgtype.UUID) []studentRef {
	resp := make([]studentRef, 0, len(ids))
	for _, id := range ids {
		resp = append(resp, studentRef{ID: uuidString(id)})
	}
	return resp
}

func mapStudentRefStrings(ids []string) []studentRef {
	resp := make([]studentRef, 0, len(ids))
	for _, id := range ids {
		resp = append(resp, studentRef{ID: id})
	}
	return resp
}

func mapCourseBase(course db.Course) map[string]interface{} {
	return map[string]interface{}{
		"id":                    uuidString(course.ID),
		"name":                  course.Name,
		"date":                  course.StartAt.Time.Unix(),
		"endDate":               course.EndAt.Time.Unix(),
		"isOnline":              course.IsOnline,
		"signatureClosingDelay": course.SignatureClosingDelayMinutes,
		"signatureClosed":       course.SignatureClosed,
		"school":                uuidString(course.SchoolID),
	}
}

func mapStudentSignatureFromGRPC(sig *attendancev1.StudentSignature) map[string]interface{} {
	entry := mapSignatureBaseFromGRPC(sig.GetId(), sig.GetCourseId(), sig.GetSignedAt(), sig.GetStatus(), sig.GetMethod(), sig.GetImage(), sig.GetAdministratorId())
	entry["student"] = sig.GetStudentId()
	if sig.GetTeacherId() != "" {
		entry["teacher"] = sig.GetTeacherId()
	}
	entry["type"] = "student"
	return entry
}

func mapTeacherSignatureFromGRPC(sig *attendancev1.TeacherSignature) map[string]interface{} {
	entry := mapSignatureBaseFromGRPC(sig.GetId(), sig.GetCourseId(), sig.GetSignedAt(), sig.GetStatus(), sig.GetMethod(), sig.GetImage(), sig.GetAdministratorId())
	entry["teacher"] = sig.GetTeacherId()
	entry["type"] = "teacher"
	return entry
}

func mapSignatureBaseFromGRPC(id, courseID string, signedAt *timestamppb.Timestamp, status, method, image, administrator string) map[string]interface{} {
	entry := map[string]interface{}{
		"id":     id,
		"course": courseID,
		"status": status,
		"method": method,
	}
	if signedAt != nil {
		entry["date"] = signedAt.AsTime().Unix()
	}
	if image != "" {
		entry["image"] = image
	}
	if administrator != "" {
		entry["administrator"] = administrator
	}
	return entry
}

func mapBeaconFromGRPC(beacon *beaconv1.Beacon) map[string]interface{} {
	entry := map[string]interface{}{
		"id":           beacon.GetId(),
		"serialNumber": beacon.GetSerialNumber(),
	}
	if beacon.GetClassroomId() != "" {
		entry["classroom"] = beacon.GetClassroomId()
	}
	if beacon.GetProgramVersion() != "" {
		entry["programVersion"] = beacon.GetProgramVersion()
	}
	return entry
}

func mapClassroomBase(room db.Classroom) map[string]interface{} {
	return map[string]interface{}{
		"id":     uuidString(room.ID),
		"name":   room.Name,
		"school": uuidString(room.SchoolID),
	}
}

func mapStudentGroupResponses(groups []db.StudentGroup) []map[string]interface{} {
	resp := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		resp = append(resp, mapStudentGroupBase(group))
	}
	return resp
}

func mapStudentGroupBase(group db.StudentGroup) map[string]interface{} {
	return map[string]interface{}{
		"id":                 uuidString(group.ID),
		"name":               group.Name,
		"singleStudentGroup": group.SingleStudentGroup,
		"school":             uuidString(group.SchoolID),
	}
}

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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type beaconRequestError struct {
	status int
	code   string
}

func (e *beaconRequestError) Error() string {
	return e.code
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

func (s *Server) assignBeaconToClassroom(ctx context.Context, authHeader, beaconID, classroomID string) error {
	payload, err := json.Marshal(map[string]string{"classroomId": classroomID})
	if err != nil {
		return err
	}
	url := strings.TrimRight(s.cfg.BeaconHTTPAddr, "/") + "/beacon/" + beaconID + "/classroom"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return beaconErrorFromResponse(resp)
}

func (s *Server) removeBeaconFromClassroom(ctx context.Context, authHeader, beaconID, classroomID string) error {
	url := strings.TrimRight(s.cfg.BeaconHTTPAddr, "/") + "/beacon/" + beaconID + "/classroom/" + classroomID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return beaconErrorFromResponse(resp)
}

func beaconErrorFromResponse(resp *http.Response) error {
	code := "beacon_assignment_failed"
	if resp.Body != nil {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err == nil && payload.Error != "" {
			code = payload.Error
		}
	}
	return &beaconRequestError{status: resp.StatusCode, code: code}
}

func nowPgTime() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
}

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func pgDate(t time.Time) pgtype.Date {
	return pgtype.Date{Time: t.UTC(), Valid: true}
}
