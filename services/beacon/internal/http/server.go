package http

import (
	"context"
	"crypto/rand"
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	attendancev1 "semaphore/attendance/attendance/v1"
	"semaphore/beacon/internal/auth"
	"semaphore/beacon/internal/config"
	"semaphore/beacon/internal/db"
)

type Server struct {
	cfg          config.Config
	store        *db.Store
	attendance   attendancev1.AttendanceCommandServiceClient
	jwtPublicKey *rsa.PublicKey
}

func NewServer(cfg config.Config, store *db.Store, attendance attendancev1.AttendanceCommandServiceClient) (*Server, error) {
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: store, attendance: attendance, jwtPublicKey: publicKey}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.Post("/beacon/auth/token", s.handleBeaconAuthToken)
	r.Post("/beacon/auth/refreshToken", s.handleBeaconRefresh)

	r.With(s.beaconAuthMiddleware).Post("/beacon/buzzLightyear", s.handleBuzzLightyear)
	r.With(s.beaconAuthMiddleware).Patch("/beacon/{beaconId}", s.handlePatchBeaconKey)

	r.With(s.authMiddleware, s.requireDev).Get("/dev/beacons", s.handleListBeacons)
	r.With(s.authMiddleware, s.requireDev).Post("/dev/beacon", s.handleCreateBeacon)
	r.With(s.authMiddleware, s.requireDev).Get("/dev/beacon/{beaconId}", s.handleGetBeacon)
	r.With(s.authMiddleware, s.requireDev).Patch("/dev/beacon/{beaconId}", s.handlePatchBeacon)
	r.With(s.authMiddleware, s.requireDev).Delete("/dev/beacon/{beaconId}", s.handleDeleteBeacon)
	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/dev/beacon/{beaconId}/classroom", s.handleAssignBeaconClassroom)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/dev/beacon/{beaconId}/classroom/{classroomId}", s.handleRemoveBeaconClassroom)

	return r
}

// Auth middleware (dev/admin)

type claimsKey struct{}

type beaconKey struct{}

type beaconContext struct {
	BeaconID string
	TokenID  string
}

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

func claimsFromContext(ctx context.Context) *auth.Claims {
	value := ctx.Value(claimsKey{})
	claims, _ := value.(*auth.Claims)
	return claims
}

func (s *Server) beaconAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing_token")
			return
		}
		hash := auth.HashToken(token)
		stored, err := s.store.Queries.GetBeaconTokenByHash(r.Context(), hash)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		if stored.ExpiresAt.Valid && stored.ExpiresAt.Time.Before(time.Now().UTC()) {
			writeError(w, http.StatusUnauthorized, "token_expired")
			return
		}
		if stored.BeaconID.Valid {
			_ = s.store.Queries.TouchBeaconToken(r.Context(), db.TouchBeaconTokenParams{
				ID:         stored.ID,
				LastUsedAt: pgTime(time.Now().UTC()),
			})
		}

		ctx := context.WithValue(r.Context(), beaconKey{}, &beaconContext{
			BeaconID: uuidString(stored.BeaconID),
			TokenID:  uuidString(stored.ID),
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func beaconFromContext(ctx context.Context) *beaconContext {
	value := ctx.Value(beaconKey{})
	beacon, _ := value.(*beaconContext)
	return beacon
}

// Models

type tokenRequest struct {
	BeaconID  string `json:"beaconId"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type tokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

type refreshRequest struct {
	BeaconID     string `json:"beaconId"`
	RefreshToken string `json:"refreshToken"`
}

type buzzLightyearRequest struct {
	BeaconID  string `json:"beaconId"`
	Code      int32  `json:"code"`
	Signature string `json:"signature"`
}

type patchBeaconKeyRequest struct {
	ID      string `json:"id"`
	TOTPKey string `json:"totpKey"`
}

type devBeaconRequest struct {
	SerialNumber   int64   `json:"serialNumber"`
	SignatureKey   string  `json:"signatureKey"`
	TOTPKey        string  `json:"totpKey"`
	Classroom      *string `json:"classroom"`
	ProgramVersion string  `json:"programVersion"`
}

type devBeaconPatchRequest struct {
	ID             string  `json:"id"`
	SerialNumber   *int64  `json:"serialNumber"`
	SignatureKey   *string `json:"signatureKey"`
	TOTPKey        *string `json:"totpKey"`
	Classroom      *string `json:"classroom"`
	ProgramVersion *string `json:"programVersion"`
}

type classroomAssignRequest struct {
	ClassroomID string `json:"classroomId"`
}

type beaconResponse struct {
	ID             string  `json:"id"`
	SerialNumber   int64   `json:"serialNumber"`
	Classroom      *string `json:"classroom,omitempty"`
	ProgramVersion *string `json:"programVersion,omitempty"`
}

// Handlers

func (s *Server) handleBeaconAuthToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.BeaconID == "" || req.Timestamp == 0 || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	beaconID, err := uuid.Parse(req.BeaconID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	beacon, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if !validateTimestamp(req.Timestamp, s.cfg.BeaconAuthWindow) {
		writeError(w, http.StatusForbidden, "invalid_timestamp")
		return
	}
	if beacon.SignatureKey == "" {
		writeError(w, http.StatusForbidden, "invalid_signature")
		return
	}

	if beacon.ID.Valid {
		_ = s.store.Queries.UpdateBeaconLastSeen(r.Context(), db.UpdateBeaconLastSeenParams{
			ID:         beacon.ID,
			LastSeenAt: pgTime(time.Now().UTC()),
		})
	}

	accessToken, refreshToken, err := s.issueBeaconTokens(r.Context(), beaconID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{Token: accessToken, RefreshToken: refreshToken})
}

func (s *Server) handleBeaconRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.BeaconID == "" || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	beaconID, err := uuid.Parse(req.BeaconID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	stored, err := s.store.Queries.GetBeaconTokenByRefresh(r.Context(), auth.HashToken(req.RefreshToken))
	if err != nil {
		writeError(w, http.StatusForbidden, "invalid_refresh_token")
		return
	}
	if !stored.BeaconID.Valid || uuidString(stored.BeaconID) != beaconID.String() {
		writeError(w, http.StatusForbidden, "invalid_refresh_token")
		return
	}
	if stored.RefreshExpiresAt.Valid && stored.RefreshExpiresAt.Time.Before(time.Now().UTC()) {
		writeError(w, http.StatusForbidden, "refresh_token_expired")
		return
	}

	_ = s.store.Queries.RevokeBeaconToken(r.Context(), db.RevokeBeaconTokenParams{
		ID:        stored.ID,
		RevokedAt: pgTime(time.Now().UTC()),
	})

	accessToken, refreshToken, err := s.issueBeaconTokens(r.Context(), beaconID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{Token: accessToken, RefreshToken: refreshToken})
}

func (s *Server) handleBuzzLightyear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	beaconCtx := beaconFromContext(ctx)
	if beaconCtx == nil || beaconCtx.BeaconID == "" {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "missing_idempotency_key")
		return
	}

	endpoint := "POST /beacon/buzzLightyear"
	beaconUUID, err := parseUUID(beaconCtx.BeaconID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if resp, ok := s.respondFromIdempotency(ctx, beaconUUID, idempotencyKey, endpoint, w); ok {
		_ = resp
		return
	}

	var req buzzLightyearRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.BeaconID == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if req.BeaconID != beaconCtx.BeaconID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	studentID := r.Header.Get("X-Student-ID")
	courseID := r.Header.Get("X-Course-ID")
	if studentID == "" || courseID == "" {
		writeError(w, http.StatusBadRequest, "missing_student_or_course")
		return
	}
	if _, err := uuid.Parse(studentID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_student_id")
		return
	}
	if _, err := uuid.Parse(courseID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_course_id")
		return
	}

	beaconID, err := uuid.Parse(req.BeaconID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}
	beacon, err := s.store.Queries.GetBeacon(ctx, pgUUID(beaconID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if beacon.ClassroomID.Valid == false {
		writeError(w, http.StatusBadRequest, "classroom_not_assigned")
		return
	}

	if beacon.ID.Valid {
		_ = s.store.Queries.UpdateBeaconLastSeen(ctx, db.UpdateBeaconLastSeenParams{
			ID:         beacon.ID,
			LastSeenAt: pgTime(time.Now().UTC()),
		})
	}

	payload, err := randomProofPayload()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "proof_generation_failed")
		return
	}

	respStatus, respBody, err := s.submitBeaconAttempt(ctx, studentID, courseID, beacon, payload)
	if err != nil {
		writeError(w, respStatus, respBody)
		return
	}

	if respStatus == http.StatusNoContent {
		s.storeIdempotency(ctx, beaconUUID, idempotencyKey, endpoint, respStatus, "")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	payloadBody, _ := json.Marshal(map[string]string{"error": respBody})
	s.storeIdempotency(ctx, beaconUUID, idempotencyKey, endpoint, respStatus, string(payloadBody))
	writeJSON(w, respStatus, map[string]string{"error": respBody})
}

func (s *Server) handlePatchBeaconKey(w http.ResponseWriter, r *http.Request) {
	beaconCtx := beaconFromContext(r.Context())
	if beaconCtx == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	pathID := chi.URLParam(r, "beaconId")
	if pathID == "" {
		writeError(w, http.StatusBadRequest, "missing_beacon_id")
		return
	}
	if pathID != beaconCtx.BeaconID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req patchBeaconKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.ID == "" || req.TOTPKey == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if req.ID != pathID {
		writeError(w, http.StatusBadRequest, "id_mismatch")
		return
	}

	beaconID, err := uuid.Parse(req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	if _, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if err := s.store.Queries.UpdateBeaconTOTP(r.Context(), db.UpdateBeaconTOTPParams{
		ID:        pgUUID(beaconID),
		TotpKey:   pgText(req.TOTPKey),
		UpdatedAt: pgTime(time.Now().UTC()),
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListBeacons(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	beacons, err := s.store.Queries.ListBeacons(r.Context(), int32(limit))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]beaconResponse, 0, len(beacons))
	for _, beacon := range beacons {
		resp = append(resp, mapBeacon(beacon))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateBeacon(w http.ResponseWriter, r *http.Request) {
	var req devBeaconRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.SerialNumber == 0 || req.SignatureKey == "" || req.TOTPKey == "" || req.ProgramVersion == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	serial := strconv.FormatInt(req.SerialNumber, 10)
	if _, err := s.store.Queries.GetBeaconBySerial(r.Context(), serial); err == nil {
		writeError(w, http.StatusConflict, "serial_number_exists")
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	classroomID := pgtype.UUID{}
	if req.Classroom != nil && *req.Classroom != "" {
		parsed, err := pgUUIDFromString(*req.Classroom)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_classroom_id")
			return
		}
		classroomID = parsed
	}

	params := db.CreateBeaconParams{
		SerialNumber:   serial,
		SignatureKey:   req.SignatureKey,
		TotpKey:        pgText(req.TOTPKey),
		ClassroomID:    classroomID,
		ProgramVersion: pgText(req.ProgramVersion),
		CreatedAt:      pgTime(time.Now().UTC()),
		UpdatedAt:      pgTime(time.Now().UTC()),
	}
	beacon, err := s.store.Queries.CreateBeacon(r.Context(), params)
	if err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "serial_number_exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, mapBeacon(beacon))
}

func (s *Server) handleGetBeacon(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "beaconId")
	beaconID, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}
	beacon, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, mapBeacon(beacon))
}

func (s *Server) handlePatchBeacon(w http.ResponseWriter, r *http.Request) {
	pathID := chi.URLParam(r, "beaconId")
	if pathID == "" {
		writeError(w, http.StatusBadRequest, "missing_beacon_id")
		return
	}

	var req devBeaconPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "missing_id")
		return
	}
	if req.ID != pathID {
		writeError(w, http.StatusBadRequest, "id_mismatch")
		return
	}
	if req.SignatureKey != nil {
		writeError(w, http.StatusBadRequest, "signature_key_readonly")
		return
	}
	beaconID, err := uuid.Parse(req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	existing, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	serial := existing.SerialNumber
	if req.SerialNumber != nil {
		serial = strconv.FormatInt(*req.SerialNumber, 10)
	}
	totp := existing.TotpKey
	if req.TOTPKey != nil {
		totp = pgText(*req.TOTPKey)
	}
	classroomID := existing.ClassroomID
	if req.Classroom != nil {
		if *req.Classroom == "" {
			writeError(w, http.StatusBadRequest, "invalid_classroom_id")
			return
		}
		parsed, err := pgUUIDFromString(*req.Classroom)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_classroom_id")
			return
		}
		classroomID = parsed
	}
	program := existing.ProgramVersion
	if req.ProgramVersion != nil {
		program = pgText(*req.ProgramVersion)
	}

	params := db.UpdateBeaconParams{
		ID:             pgUUID(beaconID),
		SerialNumber:   serial,
		TotpKey:        totp,
		ClassroomID:    classroomID,
		ProgramVersion: program,
		UpdatedAt:      pgTime(time.Now().UTC()),
	}
	_, err = s.store.Queries.UpdateBeacon(r.Context(), params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, "serial_number_exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteBeacon(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "beaconId")
	beaconID, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}
	if _, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := s.store.Queries.DeleteBeacon(r.Context(), db.DeleteBeaconParams{
		ID:        pgUUID(beaconID),
		DeletedAt: pgTime(time.Now().UTC()),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAssignBeaconClassroom(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "beaconId")
	beaconID, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}

	var req classroomAssignRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.ClassroomID == "" {
		writeError(w, http.StatusBadRequest, "missing_classroom_id")
		return
	}
	classroomID, err := uuid.Parse(req.ClassroomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}

	beacon, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if beacon.ClassroomID.Valid {
		current := uuidString(beacon.ClassroomID)
		if current != classroomID.String() {
			writeError(w, http.StatusConflict, "classroom_already_assigned")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := s.store.Queries.UpdateBeaconClassroom(r.Context(), db.UpdateBeaconClassroomParams{
		ID:          pgUUID(beaconID),
		ClassroomID: pgUUID(classroomID),
		UpdatedAt:   pgTime(time.Now().UTC()),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveBeaconClassroom(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "beaconId")
	classroomID := chi.URLParam(r, "classroomId")
	beaconID, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_beacon_id")
		return
	}
	if classroomID == "" {
		writeError(w, http.StatusBadRequest, "missing_classroom_id")
		return
	}
	if _, err := uuid.Parse(classroomID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_classroom_id")
		return
	}

	beacon, err := s.store.Queries.GetBeacon(r.Context(), pgUUID(beaconID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "beacon_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !beacon.ClassroomID.Valid || uuidString(beacon.ClassroomID) != classroomID {
		writeError(w, http.StatusNotFound, "classroom_not_assigned")
		return
	}

	if err := s.store.Queries.ClearBeaconClassroom(r.Context(), db.ClearBeaconClassroomParams{
		ID:        pgUUID(beaconID),
		UpdatedAt: pgTime(time.Now().UTC()),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Helpers

func (s *Server) issueBeaconTokens(ctx context.Context, beaconID uuid.UUID) (string, string, error) {
	accessToken, err := auth.NewOpaqueToken()
	if err != nil {
		return "", "", err
	}
	refreshToken, err := auth.NewOpaqueToken()
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	_, err = s.store.Queries.CreateBeaconToken(ctx, db.CreateBeaconTokenParams{
		ID:               pgUUID(uuid.New()),
		BeaconID:         pgUUID(beaconID),
		TokenHash:        auth.HashToken(accessToken),
		RefreshTokenHash: auth.HashToken(refreshToken),
		CreatedAt:        pgTime(now),
		ExpiresAt:        pgTime(now.Add(s.cfg.BeaconTokenTTL)),
		RefreshExpiresAt: pgTime(now.Add(s.cfg.BeaconRefreshTTL)),
		RevokedAt:        pgtype.Timestamptz{},
		LastUsedAt:       pgtype.Timestamptz{},
	})
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (s *Server) submitBeaconAttempt(ctx context.Context, studentID, courseID string, beacon db.Beacon, payload []byte) (int, string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	proof := &attendancev1.BeaconProof{
		BeaconId:     uuidString(beacon.ID),
		ClassroomId:  uuidString(beacon.ClassroomID),
		ProofType:    "buzzLightyear",
		ProofPayload: payload,
		ProofTime:    timestamppb.New(time.Now().UTC()),
	}

	resp, err := s.attendance.CreateSignatureAttempt(requestCtx, &attendancev1.CreateSignatureAttemptRequest{
		CourseId:    courseID,
		StudentId:   studentID,
		Method:      attendancev1.SignatureMethod_SIGNATURE_METHOD_FLASHLIGHT,
		BeaconProof: proof,
		ReceivedAt:  timestamppb.New(time.Now().UTC()),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return http.StatusNotFound, "course_not_found", err
		}
		if status.Code(err) == codes.InvalidArgument {
			return http.StatusBadRequest, "invalid_request", err
		}
		return http.StatusInternalServerError, "server_error", err
	}

	if resp.GetStatus() == attendancev1.SignatureStatus_SIGNATURE_STATUS_REFUSED {
		return http.StatusForbidden, resp.GetMessage(), nil
	}
	return http.StatusNoContent, "", nil
}

func (s *Server) respondFromIdempotency(ctx context.Context, beaconID pgtype.UUID, key, endpoint string, w http.ResponseWriter) (db.BeaconIdempotencyKey, bool) {
	record, err := s.store.Queries.GetBeaconIdempotency(ctx, db.GetBeaconIdempotencyParams{
		BeaconID: beaconID,
		Key:      key,
		Endpoint: endpoint,
	})
	if err != nil {
		return db.BeaconIdempotencyKey{}, false
	}
	if record.ResponseBody.Valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(record.ResponseStatus))
		_, _ = w.Write([]byte(record.ResponseBody.String))
		return record, true
	}
	w.WriteHeader(int(record.ResponseStatus))
	return record, true
}

func (s *Server) storeIdempotency(ctx context.Context, beaconID pgtype.UUID, key, endpoint string, statusCode int, body string) {
	var responseBody pgtype.Text
	if body != "" {
		responseBody = pgText(body)
	}
	_ = s.store.Queries.CreateBeaconIdempotency(ctx, db.CreateBeaconIdempotencyParams{
		ID:             pgUUID(uuid.New()),
		BeaconID:       beaconID,
		Key:            key,
		Endpoint:       endpoint,
		ResponseStatus: int32(statusCode),
		ResponseBody:   responseBody,
		CreatedAt:      pgTime(time.Now().UTC()),
	})
}

func randomProofPayload() ([]byte, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func validateTimestamp(tsMillis int64, window time.Duration) bool {
	if tsMillis <= 0 {
		return false
	}
	requestTime := time.UnixMilli(tsMillis)
	now := time.Now().UTC()
	delta := now.Sub(requestTime)
	if delta < 0 {
		delta = -delta
	}
	return delta <= window
}

func mapBeacon(beacon db.Beacon) beaconResponse {
	serial := int64(0)
	if beacon.SerialNumber != "" {
		if parsed, err := strconv.ParseInt(beacon.SerialNumber, 10, 64); err == nil {
			serial = parsed
		}
	}
	classroom := uuidString(beacon.ClassroomID)
	var classroomPtr *string
	if classroom != "" {
		classroomPtr = &classroom
	}
	var program *string
	if beacon.ProgramVersion.Valid {
		value := beacon.ProgramVersion.String
		program = &value
	}
	return beaconResponse{
		ID:             uuidString(beacon.ID),
		SerialNumber:   serial,
		Classroom:      classroomPtr,
		ProgramVersion: program,
	}
}

// Utilities

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

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func parseUUID(id string) (pgtype.UUID, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
}

func pgUUIDFromString(id string) (pgtype.UUID, error) {
	return parseUUID(id)
}

func pgText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func pgTextPtr(value *string) pgtype.Text {
	if value == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *value, Valid: *value != ""}
}

func pgTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func uuidString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
