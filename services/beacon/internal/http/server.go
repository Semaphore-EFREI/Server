package http

import (
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"semaphore/beacon/internal/auth"
	"semaphore/beacon/internal/config"
	"semaphore/beacon/internal/db"
	"semaphore/beacon/internal/operations"
)

type Server struct {
	cfg          config.Config
	store        *db.Store
	jwtPublicKey *rsa.PublicKey
}

func NewServer(cfg config.Config, store *db.Store) (*Server, error) {
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: store, jwtPublicKey: publicKey}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.With(s.authMiddleware, s.requireAdminOrDev).Get("/beacons", s.handleListBeacons)
	r.With(s.authMiddleware, s.requireDev).Post("/beacon", s.handleCreateBeacon)
	r.With(s.authMiddleware, s.requireAdminOrDev).Get("/beacon/{beaconId}", s.handleGetBeacon)
	r.With(s.authMiddleware, s.requireDev).Patch("/beacon/{beaconId}", s.handlePatchBeacon)
	r.With(s.authMiddleware, s.requireDev).Delete("/beacon/{beaconId}", s.handleDeleteBeacon)
	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/beacon/{beaconId}/classroom", s.handleAssignBeaconClassroom)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/beacon/{beaconId}/classroom/{classroomId}", s.handleRemoveBeaconClassroom)

	return r
}

// Auth middleware (dev/admin)

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

// Models

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

	var req classroomAssignRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := operations.AssignBeaconToClassroom(r.Context(), s.store, id, req.ClassroomID); err != nil {
		writeBeaconCommandError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoveBeaconClassroom(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "beaconId")
	classroomID := chi.URLParam(r, "classroomId")
	if err := operations.RemoveBeaconFromClassroom(r.Context(), s.store, id, classroomID); err != nil {
		writeBeaconCommandError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func writeBeaconCommandError(w http.ResponseWriter, err error) {
	var opErr *operations.Error
	if errors.As(err, &opErr) {
		switch opErr.Code {
		case operations.ErrInvalidBeaconID, operations.ErrMissingClassroomID, operations.ErrInvalidClassroomID:
			writeError(w, http.StatusBadRequest, opErr.Code)
			return
		case operations.ErrBeaconNotFound, operations.ErrClassroomNotAssigned:
			writeError(w, http.StatusNotFound, opErr.Code)
			return
		case operations.ErrClassroomAlreadyAssigned:
			writeError(w, http.StatusConflict, opErr.Code)
			return
		case operations.ErrServerError:
			writeError(w, http.StatusInternalServerError, opErr.Code)
			return
		}
	}
	writeError(w, http.StatusInternalServerError, operations.ErrServerError)
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
