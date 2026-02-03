package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/attendance/internal/auth"
	"semaphore/attendance/internal/config"
	"semaphore/attendance/internal/db"
	identityv1 "semaphore/auth-identity/identity/v1"
	beaconv1 "semaphore/beacon/beacon/v1"
)

type Server struct {
	cfg          config.Config
	store        *db.Store
	academics    academicsv1.AcademicsQueryServiceClient
	identity     identityv1.IdentityQueryServiceClient
	beacon       beaconv1.BeaconQueryServiceClient
	jwtPublicKey *rsa.PublicKey
	redis        *redis.Client
	buzzTTL      time.Duration
	challengeTTL time.Duration
	deviceWindow time.Duration
}

func NewServer(cfg config.Config, store *db.Store, academics academicsv1.AcademicsQueryServiceClient, identity identityv1.IdentityQueryServiceClient, beacon beaconv1.BeaconQueryServiceClient, redisClient *redis.Client) (*Server, error) {
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		store:        store,
		academics:    academics,
		identity:     identity,
		beacon:       beacon,
		jwtPublicKey: publicKey,
		redis:        redisClient,
		buzzTTL:      cfg.BuzzLightyearTTL,
		challengeTTL: cfg.SignatureChallengeTTL,
		deviceWindow: cfg.DeviceSignatureWindow,
	}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.With(s.authMiddleware).Get("/course/{courseId}/status", s.handleGetCourseStatus)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Post("/signature", s.handleCreateSignature)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Get("/signature/{signatureId}", s.handleGetSignature)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Get("/signature/buzzlightyear", s.handleGetBuzzlightyear)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Post("/signature/buzzlightyear/{beaconId}", s.handlePostBuzzlightyear)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Post("/signature/nfcCode/{beaconId}", s.handlePostNfcCode)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Get("/signature/nfcCode/{beaconId}/debug", s.handleGetNfcDebugCode)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Patch("/signature/{signatureId}", s.handlePatchSignature)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Delete("/signature/{signatureId}", s.handleDeleteSignature)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Get("/signatures", s.handleListSignatures)
	r.With(s.authMiddleware, s.studentDeviceSignatureMiddleware).Get("/signatures/report", s.handleSignatureReport)

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

func (s *Server) studentDeviceSignatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "missing_token")
			return
		}
		if claims.UserType != "student" {
			next.ServeHTTP(w, r)
			return
		}

		deviceID := strings.TrimSpace(r.Header.Get("X-Device-ID"))
		if deviceID == "" {
			writeError(w, http.StatusForbidden, "device_not_allowed")
			return
		}

		deviceResp, err := s.identity.ValidateStudentDevice(r.Context(), &identityv1.ValidateStudentDeviceRequest{
			StudentId:        claims.UserID,
			DeviceIdentifier: deviceID,
		})
		if err != nil || !deviceResp.GetIsValid() {
			writeError(w, http.StatusForbidden, "device_not_allowed")
			return
		}
		publicKey := strings.TrimSpace(deviceResp.GetPublicKey())
		if publicKey == "" {
			writeError(w, http.StatusForbidden, "device_not_allowed")
			return
		}

		timestampRaw := strings.TrimSpace(r.Header.Get("X-Device-Timestamp"))
		if timestampRaw == "" {
			writeError(w, http.StatusBadRequest, "device_signature_missing")
			return
		}
		timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "device_signature_invalid")
			return
		}
		if !withinDeviceWindow(timestamp, s.deviceWindow) {
			writeError(w, http.StatusForbidden, "device_signature_invalid")
			return
		}

		signatureRaw := strings.TrimSpace(r.Header.Get("X-Device-Signature"))
		if signatureRaw == "" {
			writeError(w, http.StatusBadRequest, "device_signature_missing")
			return
		}

		bodyBytes, err := readBodyBytes(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}

		challenge := ""
		if r.Method == http.MethodPost && r.URL.Path == "/signature" && len(bodyBytes) > 0 {
			var payload struct {
				Challenge string `json:"challenge"`
			}
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_request")
				return
			}
			challenge = strings.TrimSpace(payload.Challenge)
		}

		bodyHash := hashBodyBase64(bodyBytes)
		message := deviceSignatureMessage(r.Method, r.URL.Path, claims.UserID, deviceID, timestampRaw, bodyHash, challenge)
		pubKey, err := parseECDSAPublicKey(publicKey)
		if err != nil {
			writeError(w, http.StatusForbidden, "device_not_allowed")
			return
		}
		signatureBytes, err := decodeBase64(signatureRaw)
		if err != nil {
			writeError(w, http.StatusForbidden, "device_signature_invalid")
			return
		}
		digest := sha256.Sum256([]byte(message))
		if !ecdsa.VerifyASN1(pubKey, digest[:], signatureBytes) {
			writeError(w, http.StatusForbidden, "device_signature_invalid")
			return
		}

		next.ServeHTTP(w, r)
	})
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
	Teacher       string `json:"teacher"`
	Administrator string `json:"administrator,omitempty"`
}

type createSignatureRequest struct {
	Date      int64   `json:"date"`
	Course    string  `json:"course"`
	Status    string  `json:"status"`
	Image     *string `json:"image"`
	Method    string  `json:"method"`
	Student   string  `json:"student"`
	Teacher   string  `json:"teacher"`
	Challenge string  `json:"challenge"`
}

type patchSignatureRequest struct {
	Status *string `json:"status"`
	Image  *string `json:"image"`
}

// Handlers

func (s *Server) handleCreateSignature(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" && claims.UserType != "teacher" && claims.UserType != "admin" {
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
	var adminID *string
	if claims.UserType == "student" {
		if req.Student == "" {
			req.Student = claims.UserID
		}
		if req.Student != claims.UserID || req.Teacher != "" {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.validateStudentDevice(r.Context(), req.Student, r.Header.Get("X-Device-ID")) {
			writeError(w, http.StatusForbidden, "device_not_allowed")
			return
		}
	} else if claims.UserType == "teacher" {
		if req.Teacher == "" {
			req.Teacher = claims.UserID
		}
		if req.Teacher != claims.UserID {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	} else {
		if req.Student == "" && req.Teacher == "" {
			writeError(w, http.StatusBadRequest, "missing_teacher")
			return
		}
		adminUserID := claims.UserID
		adminID = &adminUserID
	}

	isStudentSignature := req.Student != ""

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

	if claims.UserType == "admin" && claims.SchoolID != "" && claims.SchoolID != course.GetSchoolId() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if isStudentSignature {
		allowed, err := s.academics.ValidateStudentCourse(r.Context(), &academicsv1.ValidateStudentCourseRequest{
			StudentId: req.Student,
			CourseId:  req.Course,
		})
		if err != nil || !allowed.GetIsAllowed() {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	if req.Teacher != "" {
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
	if claims.UserType == "teacher" {
		methodValue = db.SignatureMethodTeacher
	} else if claims.UserType == "admin" {
		methodValue = db.SignatureMethodAdmin
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

		if requiresChallengeForMethod(methodValue) {
			if strings.TrimSpace(req.Challenge) == "" {
				writeError(w, http.StatusForbidden, "challenge_missing")
				return
			}
			if s.redis == nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			record, ok, err := s.consumeSignatureChallenge(r.Context(), strings.TrimSpace(req.Challenge))
			if err != nil {
				writeError(w, http.StatusInternalServerError, "server_error")
				return
			}
			if !ok {
				writeError(w, http.StatusForbidden, "challenge_missing")
				return
			}
			now := time.Now().UTC().Unix()
			if record.ExpiresAt > 0 && now > record.ExpiresAt {
				writeError(w, http.StatusForbidden, "challenge_expired")
				return
			}
			deviceID := strings.TrimSpace(r.Header.Get("X-Device-ID"))
			if record.CourseID != req.Course || record.StudentID != req.Student || record.DeviceID != deviceID || record.Method != string(methodValue) {
				writeError(w, http.StatusForbidden, "challenge_mismatch")
				return
			}
		}
	}

	if claims.UserType == "student" {
		timingStatus, timingErr := validateTiming(course, signedAt)
		if timingErr != "" {
			writeError(w, http.StatusForbidden, timingErr)
			return
		}
		if timingStatus != "" {
			statusValue = db.SignatureStatus(timingStatus)
		}
	}

	if isStudentSignature {
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
		if isStudentSignature {
			return q.CreateStudentSignature(r.Context(), db.CreateStudentSignatureParams{
				SignatureID:     pgUUID(signatureID),
				StudentID:       pgUUIDFromString(req.Student),
				TeacherID:       pgUUIDFromString(req.Teacher),
				AdministratorID: pgUUIDFromStringPtr(adminID),
				CourseID:        courseID,
			})
		}
		return q.CreateTeacherSignature(r.Context(), db.CreateTeacherSignatureParams{
			SignatureID:     pgUUID(signatureID),
			TeacherID:       pgUUIDFromString(req.Teacher),
			AdministratorID: pgUUIDFromStringPtr(adminID),
			CourseID:        courseID,
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

	if isStudentSignature {
		administrator := ""
		if adminID != nil {
			administrator = *adminID
		}
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
			Administrator: administrator,
		}
		if req.Image != nil {
			resp.Image = *req.Image
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	administrator := ""
	if adminID != nil {
		administrator = *adminID
	}
	resp := teacherSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     signatureID.String(),
			Date:   signedAt.Unix(),
			Course: req.Course,
			Status: string(statusValue),
			Method: string(methodValue),
		},
		Teacher:       req.Teacher,
		Administrator: administrator,
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
	if strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	code, err := randomBuzzLightyearCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if err := s.storeBuzzLightyearCode(r.Context(), claims.UserID, code); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]int32{
		"code":     code,
		"validity": int32(s.buzzTTL.Seconds()),
	})
}

func (s *Server) handlePostBuzzlightyear(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	beaconID := chi.URLParam(r, "beaconId")
	if beaconID == "" {
		writeError(w, http.StatusBadRequest, "missing_beacon_id")
		return
	}
	if _, err := uuid.Parse(beaconID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	var req struct {
		Signature string `json:"signature"`
		CourseID  string `json:"courseId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.Signature) == "" {
		writeError(w, http.StatusBadRequest, "missing_signature")
		return
	}
	if strings.TrimSpace(req.CourseID) == "" {
		writeError(w, http.StatusBadRequest, "missing_course")
		return
	}
	if _, err := uuid.Parse(req.CourseID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course")
		return
	}

	code, ok, err := s.loadBuzzLightyearCode(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "code_not_found")
		return
	}
	_ = s.clearBuzzLightyearCode(r.Context(), claims.UserID)

	courseResp, err := s.academics.GetCourse(r.Context(), &academicsv1.GetCourseRequest{CourseId: req.CourseID})
	if err != nil || courseResp.GetCourse() == nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	allowed, err := s.academics.ValidateStudentCourse(r.Context(), &academicsv1.ValidateStudentCourseRequest{
		StudentId: claims.UserID,
		CourseId:  req.CourseID,
	})
	if err != nil || !allowed.GetIsAllowed() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	prefs, err := s.loadSchoolPreferences(r.Context(), courseResp.GetCourse().GetSchoolId())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "preferences_not_found")
		return
	}
	if !methodAllowedForStudent(db.SignatureMethod("buzzLightyear"), prefs) {
		writeError(w, http.StatusForbidden, "method_not_allowed")
		return
	}

	if s.beacon == nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	proofResp, err := s.beacon.ValidateBuzzLightyearProof(r.Context(), &beaconv1.ValidateBuzzLightyearProofRequest{
		BeaconId:  beaconID,
		Code:      code,
		Signature: req.Signature,
		StudentId: claims.UserID,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound:
			writeError(w, http.StatusNotFound, "beacon_not_found")
		case codes.InvalidArgument:
			writeError(w, http.StatusBadRequest, "invalid_request")
		case codes.FailedPrecondition:
			writeError(w, http.StatusForbidden, "invalid_signature_key")
		default:
			writeError(w, http.StatusInternalServerError, "server_error")
		}
		return
	}
	if !proofResp.GetIsValid() {
		switch proofResp.GetErrorCode() {
		case "classroom_not_assigned":
			writeError(w, http.StatusForbidden, "beacon_not_assigned")
		case "proof_replay":
			writeError(w, http.StatusConflict, "proof_replay")
		default:
			writeError(w, http.StatusForbidden, "invalid_signature")
		}
		return
	}
	if strings.TrimSpace(proofResp.GetClassroomId()) == "" {
		writeError(w, http.StatusForbidden, "beacon_not_assigned")
		return
	}
	classroomResp, err := s.academics.ValidateClassroomCourse(r.Context(), &academicsv1.ValidateClassroomCourseRequest{
		ClassroomId: proofResp.GetClassroomId(),
		CourseId:    req.CourseID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !classroomResp.GetIsLinked() {
		writeError(w, http.StatusForbidden, "beacon_not_linked")
		return
	}

	if s.redis == nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	challenge, err := randomChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	now := time.Now().UTC()
	record := signatureChallengeRecord{
		CourseID:  req.CourseID,
		StudentID: claims.UserID,
		DeviceID:  strings.TrimSpace(r.Header.Get("X-Device-ID")),
		Method:    "buzzLightyear",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.challengeTTL).Unix(),
	}
	if err := s.storeSignatureChallenge(r.Context(), challenge, record); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	_ = code
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": challenge,
		"expiresIn": int64(s.challengeTTL.Seconds()),
	})
}

func (s *Server) handlePostNfcCode(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	beaconID := chi.URLParam(r, "beaconId")
	if beaconID == "" {
		writeError(w, http.StatusBadRequest, "missing_beacon_id")
		return
	}
	if _, err := uuid.Parse(beaconID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	var req struct {
		TotpCode string `json:"totpCode"`
		CourseID string `json:"courseId"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if strings.TrimSpace(req.TotpCode) == "" {
		writeError(w, http.StatusBadRequest, "missing_totp_code")
		return
	}
	if strings.TrimSpace(req.CourseID) == "" {
		writeError(w, http.StatusBadRequest, "missing_course")
		return
	}
	if _, err := uuid.Parse(req.CourseID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course")
		return
	}

	courseResp, err := s.academics.GetCourse(r.Context(), &academicsv1.GetCourseRequest{CourseId: req.CourseID})
	if err != nil || courseResp.GetCourse() == nil {
		writeError(w, http.StatusNotFound, "course_not_found")
		return
	}
	allowed, err := s.academics.ValidateStudentCourse(r.Context(), &academicsv1.ValidateStudentCourseRequest{
		StudentId: claims.UserID,
		CourseId:  req.CourseID,
	})
	if err != nil || !allowed.GetIsAllowed() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	prefs, err := s.loadSchoolPreferences(r.Context(), courseResp.GetCourse().GetSchoolId())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "preferences_not_found")
		return
	}
	if !methodAllowedForStudent(db.SignatureMethod("nfc"), prefs) {
		writeError(w, http.StatusForbidden, "method_not_allowed")
		return
	}

	if s.beacon == nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	resp, err := s.beacon.ValidateNfcCode(r.Context(), &beaconv1.ValidateNfcCodeRequest{
		BeaconId: beaconID,
		TotpCode: req.TotpCode,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !resp.GetIsValid() {
		switch resp.GetErrorCode() {
		case "classroom_not_assigned":
			writeError(w, http.StatusForbidden, "beacon_not_assigned")
		case "invalid_totp_code":
			writeError(w, http.StatusForbidden, "invalid_totp_code")
		case "totp_key_missing":
			writeError(w, http.StatusForbidden, "invalid_totp_key")
		default:
			writeError(w, http.StatusForbidden, "invalid_totp_code")
		}
		return
	}
	if strings.TrimSpace(resp.GetClassroomId()) == "" {
		writeError(w, http.StatusForbidden, "beacon_not_assigned")
		return
	}
	classroomResp, err := s.academics.ValidateClassroomCourse(r.Context(), &academicsv1.ValidateClassroomCourseRequest{
		ClassroomId: resp.GetClassroomId(),
		CourseId:    req.CourseID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !classroomResp.GetIsLinked() {
		writeError(w, http.StatusForbidden, "beacon_not_linked")
		return
	}

	if s.redis == nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	challenge, err := randomChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	now := time.Now().UTC()
	record := signatureChallengeRecord{
		CourseID:  req.CourseID,
		StudentID: claims.UserID,
		DeviceID:  strings.TrimSpace(r.Header.Get("X-Device-ID")),
		Method:    "nfc",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.challengeTTL).Unix(),
	}
	if err := s.storeSignatureChallenge(r.Context(), challenge, record); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": challenge,
		"expiresIn": int64(s.challengeTTL.Seconds()),
	})
}

func (s *Server) handleGetNfcDebugCode(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.NfcDebugEnabled {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "admin" && claims.UserType != "dev" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	beaconID := chi.URLParam(r, "beaconId")
	if beaconID == "" {
		writeError(w, http.StatusBadRequest, "missing_beacon_id")
		return
	}
	if _, err := uuid.Parse(beaconID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}
	if s.beacon == nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	resp, err := s.beacon.GetNfcCode(r.Context(), &beaconv1.GetNfcCodeRequest{
		BeaconId: beaconID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totpCode":          resp.GetTotpCode(),
		"generatedAt":       resp.GetGeneratedAt(),
		"secretFingerprint": resp.GetSecretFingerprint(),
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
	deletedAt := nowPgTime()
	if err := s.store.Queries.SoftDeleteSignature(r.Context(), db.SoftDeleteSignatureParams{ID: sigUUID, DeletedAt: deletedAt}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := s.store.Queries.SoftDeleteStudentSignature(r.Context(), db.SoftDeleteStudentSignatureParams{SignatureID: sigUUID, DeletedAt: deletedAt}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := s.store.Queries.SoftDeleteTeacherSignature(r.Context(), db.SoftDeleteTeacherSignatureParams{SignatureID: sigUUID, DeletedAt: deletedAt}); err != nil {
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
		if sig.Status == db.SignatureStatusPresent {
			if req.Status == nil {
				return &patchError{status: http.StatusBadRequest, code: "missing_status"}
			}
			parsed, err := normalizeStatus(*req.Status)
			if err != nil {
				return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
			}
			if parsed != db.SignatureStatusSigned {
				return &patchError{status: http.StatusForbidden, code: "forbidden"}
			}
			if req.Image == nil {
				return &patchError{status: http.StatusBadRequest, code: "missing_image"}
			}
			imageValue := pgText(req.Image)
			if err := s.updateSignature(ctx, sig.ID, parsed, sig.Method, imageValue, sig.SignedAt.Time); err != nil {
				return &patchError{status: http.StatusInternalServerError, code: "server_error"}
			}
			return nil
		}
		if sig.Status == db.SignatureStatusSigned {
			if req.Image == nil {
				return &patchError{status: http.StatusBadRequest, code: "missing_image"}
			}
			statusValue := sig.Status
			if req.Status != nil {
				parsed, err := normalizeStatus(*req.Status)
				if err != nil {
					return &patchError{status: http.StatusBadRequest, code: "invalid_status"}
				}
				if parsed != db.SignatureStatusSigned {
					return &patchError{status: http.StatusForbidden, code: "forbidden"}
				}
				statusValue = parsed
			}
			imageValue := pgText(req.Image)
			if err := s.updateSignature(ctx, sig.ID, statusValue, sig.Method, imageValue, sig.SignedAt.Time); err != nil {
				return &patchError{status: http.StatusInternalServerError, code: "server_error"}
			}
			return nil
		}
		return &patchError{status: http.StatusForbidden, code: "forbidden"}
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
		if err := s.updateSignature(ctx, sig.ID, statusValue, db.SignatureMethodTeacher, imageValue, sig.SignedAt.Time); err != nil {
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
		if err := s.updateSignature(ctx, sig.ID, statusValue, db.SignatureMethodAdmin, sig.ImageUrl, sig.SignedAt.Time); err != nil {
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
		if err := s.updateSignature(ctx, sig.ID, statusValue, db.SignatureMethodTeacher, imageValue, sig.SignedAt.Time); err != nil {
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
		if err := s.updateSignature(ctx, sig.ID, statusValue, db.SignatureMethodAdmin, sig.ImageUrl, sig.SignedAt.Time); err != nil {
			return &patchError{status: http.StatusInternalServerError, code: "server_error"}
		}
		_ = s.store.Queries.UpdateTeacherSignature(ctx, db.UpdateTeacherSignatureParams{
			SignatureID:     sig.ID,
			AdministratorID: pgUUIDFromString(claims.UserID),
		})
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
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID, sig.AdministratorID)
}

func mapTeacherSignatureFromListTeacher(sig db.ListTeacherSignaturesByTeacherRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID, sig.AdministratorID)
}

func mapTeacherSignatureFromListTeacherCourse(sig db.ListTeacherSignaturesByTeacherAndCourseRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID, sig.AdministratorID)
}

func mapTeacherSignatureFromListCourse(sig db.ListTeacherSignaturesByCourseRow) teacherSignatureResponse {
	return mapTeacherSignatureValues(sig.ID, sig.CourseID, sig.SignedAt, sig.Status, sig.Method, sig.ImageUrl, sig.TeacherID, sig.AdministratorID)
}

func mapTeacherSignatureValues(id, courseID pgtype.UUID, signedAt pgtype.Timestamptz, status db.SignatureStatus, method db.SignatureMethod, image pgtype.Text, teacherID, adminID pgtype.UUID) teacherSignatureResponse {
	resp := teacherSignatureResponse{
		signatureBaseResponse: signatureBaseResponse{
			ID:     uuidString(id),
			Date:   signedAt.Time.Unix(),
			Course: uuidString(courseID),
			Status: string(status),
			Method: string(method),
		},
		Teacher:       uuidString(teacherID),
		Administrator: uuidString(adminID),
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
	case "nfc":
		return db.SignatureMethod("nfc"), nil
	case "beacon", "buzzLightyear", "teacher", "web", "self", "admin":
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
	case "buzzLightyear", "beacon":
		return prefs.GetEnableFlash()
	case "nfc":
		return prefs.GetEnableNfc()
	default:
		return true
	}
}

func requiresChallengeForMethod(method db.SignatureMethod) bool {
	switch string(method) {
	case "buzzLightyear", "nfc":
		return true
	default:
		return false
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

func (s *Server) storeBuzzLightyearCode(ctx context.Context, userID string, code int32) error {
	if s.redis == nil {
		return errors.New("redis_not_configured")
	}
	key := buzzLightyearKey(userID)
	return s.redis.Set(ctx, key, strconv.FormatInt(int64(code), 10), s.buzzTTL).Err()
}

func (s *Server) loadBuzzLightyearCode(ctx context.Context, userID string) (int32, bool, error) {
	if s.redis == nil {
		return 0, false, errors.New("redis_not_configured")
	}
	key := buzzLightyearKey(userID)
	value, err := s.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false, err
	}
	return int32(parsed), true, nil
}

func (s *Server) clearBuzzLightyearCode(ctx context.Context, userID string) error {
	if s.redis == nil {
		return errors.New("redis_not_configured")
	}
	key := buzzLightyearKey(userID)
	return s.redis.Del(ctx, key).Err()
}

func buzzLightyearKey(userID string) string {
	return fmt.Sprintf("buzzlightyear:%s", userID)
}

type signatureChallengeRecord struct {
	CourseID  string `json:"course_id"`
	StudentID string `json:"student_id"`
	DeviceID  string `json:"device_id"`
	Method    string `json:"method"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func randomChallenge() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Server) storeSignatureChallenge(ctx context.Context, challenge string, record signatureChallengeRecord) error {
	if s.redis == nil {
		return errors.New("redis_not_configured")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, signatureChallengeKey(challenge), data, s.challengeTTL).Err()
}

func (s *Server) consumeSignatureChallenge(ctx context.Context, challenge string) (signatureChallengeRecord, bool, error) {
	if s.redis == nil {
		return signatureChallengeRecord{}, false, nil
	}
	value, err := s.redis.GetDel(ctx, signatureChallengeKey(challenge)).Result()
	if err == redis.Nil {
		return signatureChallengeRecord{}, false, nil
	}
	if err != nil {
		return signatureChallengeRecord{}, false, err
	}
	var record signatureChallengeRecord
	if err := json.Unmarshal([]byte(value), &record); err != nil {
		return signatureChallengeRecord{}, false, err
	}
	return record, true, nil
}

func signatureChallengeKey(challenge string) string {
	return fmt.Sprintf("signature_challenge:%s", challenge)
}

func withinDeviceWindow(timestamp int64, window time.Duration) bool {
	if timestamp <= 0 {
		return false
	}
	requestTime := time.Unix(timestamp, 0).UTC()
	now := time.Now().UTC()
	delta := now.Sub(requestTime)
	if delta < 0 {
		delta = -delta
	}
	return delta <= window
}

func readBodyBytes(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func hashBodyBase64(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func deviceSignatureMessage(method, path, studentID, deviceID, timestamp, bodyHash, challenge string) string {
	parts := []string{method, path, studentID, deviceID, timestamp, bodyHash, challenge}
	return strings.Join(parts, "\n")
}

func parseECDSAPublicKey(pemValue string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("invalid_public_key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid_public_key_type")
	}
	if publicKey.Curve == nil || publicKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("invalid_public_key_curve")
	}
	return publicKey, nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
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

func pgUUIDFromStringPtr(id *string) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgUUIDFromString(*id)
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
