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
	"github.com/prometheus/client_golang/prometheus/promhttp"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/auth-identity/internal/auth"
	"semaphore/auth-identity/internal/config"
	"semaphore/auth-identity/internal/crypto"
	"semaphore/auth-identity/internal/model"
	"semaphore/auth-identity/internal/repository"
)

type Server struct {
	cfg           config.Config
	store         *repository.Store
	jwtPrivateKey *rsa.PrivateKey
	jwtPublicKey  *rsa.PublicKey
	jwks          auth.JWKSet
	academics     academicsv1.AcademicsQueryServiceClient
}

func NewServer(cfg config.Config, store *repository.Store, academics academicsv1.AcademicsQueryServiceClient) (*Server, error) {
	privateKey, err := auth.ParseRSAPrivateKey(cfg.JWTPrivateKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := auth.ParseRSAPublicKey(cfg.JWTPublicKey)
	if err != nil {
		return nil, err
	}
	jwks, err := auth.NewJWKSet(publicKey)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:           cfg,
		store:         store,
		jwtPrivateKey: privateKey,
		jwtPublicKey:  publicKey,
		jwks:          jwks,
		academics:     academics,
	}, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Handle("/metrics", promhttp.Handler())
	r.Get("/.well-known/jwks.json", s.handleJWKS)

	r.Post("/auth/login", s.handleLogin)
	r.Post("/auth/refresh", s.handleRefresh)
	r.With(s.authMiddleware).Post("/auth/logout", s.handleLogout)

	r.With(s.authMiddleware).Get("/auth/me", s.handleGetMe)
	r.With(s.authMiddleware).Post("/students/me/devices", s.handleRegisterDevice)
	r.With(s.authMiddleware).Get("/student/{studentId}/device", s.handleGetStudentDevice)
	r.With(s.authMiddleware).Put("/student/{studentId}/device", s.handlePutStudentDevice)

	r.Route("/students", func(r chi.Router) {
		r.With(s.authMiddleware, s.requireAdminOrDev).Get("/{schoolId}", s.handleGetStudentsBySchool)
	})

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/student", s.handleCreateStudent)
	r.With(s.authMiddleware).Get("/student/{studentId}", s.handleGetStudent)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/student/{studentId}", s.handlePatchStudent)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/student/{studentId}", s.handleDeleteStudent)

	r.Route("/teachers", func(r chi.Router) {
		r.With(s.authMiddleware, s.requireAdminOrDev).Get("/{schoolId}", s.handleGetTeachersBySchool)
	})

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/teacher", s.handleCreateTeacher)
	r.With(s.authMiddleware).Get("/teacher/{teacherId}", s.handleGetTeacher)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/teacher/{teacherId}", s.handlePatchTeacher)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/teacher/{teacherId}", s.handleDeleteTeacher)

	r.Route("/admins", func(r chi.Router) {
		r.With(s.authMiddleware, s.requireAdminOrDev).Get("/{schoolId}", s.handleGetAdminsBySchool)
	})

	r.With(s.authMiddleware, s.requireAdminOrDev).Post("/admin", s.handleCreateAdmin)
	r.With(s.authMiddleware, s.requireAdminOrDev).Get("/admin/{adminId}", s.handleGetAdmin)
	r.With(s.authMiddleware, s.requireAdminOrDev).Patch("/admin/{adminId}", s.handlePatchAdmin)
	r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/admin/{adminId}", s.handleDeleteAdmin)

	r.Route("/users", func(r chi.Router) {
		r.With(s.authMiddleware, s.requireAdminOrDev).Get("/", s.handleListUsers)
		r.With(s.authMiddleware, s.requireAdminOrDev).Post("/", s.handleCreateUser)
		r.With(s.authMiddleware).Get("/{userID}", s.handleGetUser)
		r.With(s.authMiddleware).Patch("/{userID}", s.handleUpdateUser)
		r.With(s.authMiddleware, s.requireAdminOrDev).Delete("/{userID}", s.handleDeleteUser)
	})

	return r
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
	User         userSummary `json:"user"`
}

type userSummary struct {
	ID        string  `json:"id"`
	SchoolID  string  `json:"schoolId"`
	Email     string  `json:"email"`
	FirstName string  `json:"firstName"`
	LastName  string  `json:"lastName"`
	UserType  string  `json:"userType"`
	AdminRole *string `json:"adminRole,omitempty"`
	StudentNo *string `json:"studentNumber,omitempty"`
}

type studentSummary struct {
	ID            string    `json:"id"`
	FirstName     string    `json:"firstname"`
	LastName      string    `json:"lastname"`
	Email         string    `json:"email"`
	CreatedOn     int64     `json:"createdOn"`
	StudentNumber int64     `json:"studentNumber"`
	SchoolID      string    `json:"school,omitempty"`
	Groups        *[]string `json:"groups,omitempty"`
}

type teacherSummary struct {
	ID        string `json:"id"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	CreatedOn int64  `json:"createdOn"`
	SchoolID  string `json:"school,omitempty"`
}

type adminSummary struct {
	ID        string `json:"id"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	CreatedOn int64  `json:"createdOn"`
	Role      string `json:"role"`
	SchoolID  string `json:"school,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "missing_credentials")
		return
	}

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if err := crypto.CheckPassword(user.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	role, err := s.store.GetRole(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "role_not_found")
		return
	}

	accessToken, refreshToken, err := s.issueTokens(r.Context(), user, role, r.UserAgent(), clientIP(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error")
		return
	}

	resp := authResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: userSummary{
			ID:        user.ID,
			SchoolID:  user.SchoolID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			UserType:  role.UserType,
			AdminRole: role.AdminRole,
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "missing_refresh_token")
		return
	}

	tokenHash := crypto.HashToken(req.RefreshToken)
	session, err := s.store.GetRefreshSession(r.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "invalid_refresh_token")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	if session.RevokedAt != nil || session.ExpiresAt.Before(time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "refresh_token_expired")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user_not_found")
		return
	}

	role, err := s.store.GetRole(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "role_not_found")
		return
	}

	if err := s.store.RevokeRefreshSession(r.Context(), session.ID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	accessToken, refreshToken, err := s.issueTokens(r.Context(), user, role, r.UserAgent(), clientIP(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error")
		return
	}

	resp := authResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: userSummary{
			ID:        user.ID,
			SchoolID:  user.SchoolID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			UserType:  role.UserType,
			AdminRole: role.AdminRole,
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	_ = s.store.RevokeRefreshSessionsByUser(r.Context(), claims.UserID, time.Now().UTC())
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type registerDeviceRequest struct {
	DeviceIdentifier string  `json:"device_identifier"`
	PublicKey        *string `json:"public_key"`
}

type deviceResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

type putStudentDeviceRequest struct {
	ID        *string `json:"id,omitempty"`
	Name      string  `json:"name"`
	CreatedAt *string `json:"createdAt,omitempty"`
	PublicKey string  `json:"publicKey"`
}

type deviceRegistrationResult struct {
	Device model.Device
	Status int
}

func (s *Server) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil || claims.UserType != "student" {
		writeError(w, http.StatusForbidden, "student_only")
		return
	}

	var req registerDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.DeviceIdentifier = strings.TrimSpace(req.DeviceIdentifier)
	if req.DeviceIdentifier == "" {
		writeError(w, http.StatusBadRequest, "missing_device_identifier")
		return
	}

	result, errCode, err := s.registerDevice(r.Context(), claims.UserID, req.DeviceIdentifier, req.PublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if errCode != "" {
		writeError(w, http.StatusConflict, errCode)
		return
	}
	if result.Status == http.StatusOK {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

func (s *Server) handleGetStudentDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	studentID := chi.URLParam(r, "studentId")
	if studentID == "" {
		writeError(w, http.StatusBadRequest, "missing_student_id")
		return
	}

	if claims.UserType == "teacher" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if claims.UserType == "student" && claims.UserID != studentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if claims.UserType != "student" && !isAdminOrDev(claims) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	device, err := s.store.GetActiveDevice(r.Context(), studentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "device_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusOK, mapDeviceResponse(device))
}

func (s *Server) handlePutStudentDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if claims.UserType != "student" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	studentID := chi.URLParam(r, "studentId")
	if studentID == "" {
		writeError(w, http.StatusBadRequest, "missing_student_id")
		return
	}
	if claims.UserID != studentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req putStudentDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.Name == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}

	result, errCode, err := s.registerDevice(r.Context(), studentID, req.Name, &req.PublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if errCode != "" {
		writeError(w, http.StatusConflict, errCode)
		return
	}

	writeJSON(w, http.StatusOK, mapDeviceResponse(result.Device))
}

func (s *Server) registerDevice(ctx context.Context, studentID, deviceIdentifier string, publicKey *string) (deviceRegistrationResult, string, error) {
	now := time.Now().UTC()
	activeDevice, err := s.store.GetActiveDevice(ctx, studentID)
	if err == nil {
		if activeDevice.DeviceIdentifier == deviceIdentifier {
			_ = s.store.UpdateDeviceLastSeen(ctx, activeDevice.ID, now)
			activeDevice.LastSeenAt = &now
			return deviceRegistrationResult{Device: activeDevice, Status: http.StatusOK}, "", nil
		}
		if activeDevice.RegisteredAt.After(now.Add(-s.cfg.DeviceRebindAfter)) {
			return deviceRegistrationResult{}, "device_rebind_too_soon", nil
		}
		if err := s.store.DeactivateDevices(ctx, studentID, now); err != nil {
			return deviceRegistrationResult{}, "", err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return deviceRegistrationResult{}, "", err
	}

	device := model.Device{
		ID:               uuid.NewString(),
		StudentID:        studentID,
		DeviceIdentifier: deviceIdentifier,
		PublicKey:        publicKey,
		RegisteredAt:     now,
		LastSeenAt:       &now,
		Active:           true,
	}
	if err := s.store.CreateDevice(ctx, device); err != nil {
		return deviceRegistrationResult{}, "", err
	}

	return deviceRegistrationResult{Device: device, Status: http.StatusCreated}, "", nil
}

func mapDeviceResponse(device model.Device) deviceResponse {
	resp := deviceResponse{
		ID:   device.ID,
		Name: device.DeviceIdentifier,
	}
	if !device.RegisteredAt.IsZero() {
		resp.CreatedAt = device.RegisteredAt.UTC().Format(time.RFC3339)
	}
	return resp
}

type createUserRequest struct {
	Email         string  `json:"email"`
	Password      string  `json:"password"`
	FirstName     string  `json:"firstName"`
	LastName      string  `json:"lastName"`
	SchoolID      string  `json:"schoolId"`
	UserType      string  `json:"userType"`
	AdminRole     *string `json:"adminRole,omitempty"`
	StudentNumber *string `json:"studentNumber,omitempty"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.UserType = strings.TrimSpace(strings.ToLower(req.UserType))
	if req.AdminRole != nil {
		role := strings.TrimSpace(strings.ToLower(*req.AdminRole))
		req.AdminRole = &role
	}
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" || req.SchoolID == "" || req.UserType == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if req.UserType == "student" && (req.StudentNumber == nil || strings.TrimSpace(*req.StudentNumber) == "") {
		writeError(w, http.StatusBadRequest, "student_number_required")
		return
	}
	if req.UserType == "admin" && req.AdminRole != nil && !isValidAdminRole(*req.AdminRole) {
		writeError(w, http.StatusBadRequest, "invalid_admin_role")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	now := time.Now().UTC()
	user := model.User{
		ID:           uuid.NewString(),
		SchoolID:     req.SchoolID,
		Email:        req.Email,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.store.CreateUserWithRole(r.Context(), user, req.UserType, req.AdminRole, req.StudentNumber); err != nil {
		writeError(w, http.StatusBadRequest, "user_create_failed")
		return
	}

	resp := userSummary{
		ID:        user.ID,
		SchoolID:  user.SchoolID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserType:  req.UserType,
	}
	if req.UserType == "admin" {
		resp.AdminRole = req.AdminRole
	}
	if req.UserType == "student" && req.StudentNumber != nil {
		studentNumber := strings.TrimSpace(*req.StudentNumber)
		if studentNumber != "" {
			resp.StudentNo = &studentNumber
		}
	}

	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	users, err := s.store.ListUsers(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	summaries := make([]userSummary, 0, len(users))
	for _, user := range users {
		role, err := s.store.GetRole(r.Context(), user.ID)
		if err != nil {
			continue
		}
		summary := userSummary{
			ID:        user.ID,
			SchoolID:  user.SchoolID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			UserType:  role.UserType,
			AdminRole: role.AdminRole,
		}
		if role.UserType == "student" {
			if profile, err := s.store.GetStudentProfile(r.Context(), user.ID); err == nil {
				studentNumber := profile.StudentNumber
				summary.StudentNo = &studentNumber
			}
		}
		summaries = append(summaries, summary)
	}

	writeJSON(w, http.StatusOK, summaries)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "missing_user_id")
		return
	}
	if !isAdminOrDev(claims) && claims.UserID != userID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user_not_found")
		return
	}
	role, err := s.store.GetRole(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "role_not_found")
		return
	}

	summary := userSummary{
		ID:        user.ID,
		SchoolID:  user.SchoolID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserType:  role.UserType,
		AdminRole: role.AdminRole,
	}
	if role.UserType == "student" {
		if profile, err := s.store.GetStudentProfile(r.Context(), user.ID); err == nil {
			studentNumber := profile.StudentNumber
			summary.StudentNo = &studentNumber
		}
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user_not_found")
		return
	}
	role, err := s.store.GetRole(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "role_not_found")
		return
	}

	summary := userSummary{
		ID:        user.ID,
		SchoolID:  user.SchoolID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserType:  role.UserType,
		AdminRole: role.AdminRole,
	}
	if role.UserType == "student" {
		if profile, err := s.store.GetStudentProfile(r.Context(), user.ID); err == nil {
			studentNumber := profile.StudentNumber
			summary.StudentNo = &studentNumber
		}
	}
	writeJSON(w, http.StatusOK, summary)
}

type updateUserRequest struct {
	Email     *string `json:"email,omitempty"`
	Password  *string `json:"password,omitempty"`
	FirstName *string `json:"firstName,omitempty"`
	LastName  *string `json:"lastName,omitempty"`
	SchoolID  *string `json:"schoolId,omitempty"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "missing_user_id")
		return
	}

	isPrivileged := isAdminOrDev(claims)
	if !isPrivileged && claims.UserID != userID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	update := repository.UserUpdate{}
	if req.Email != nil && isPrivileged {
		email := strings.TrimSpace(strings.ToLower(*req.Email))
		if email != "" {
			update.Email = &email
		}
	}
	if req.SchoolID != nil && isPrivileged {
		schoolID := strings.TrimSpace(*req.SchoolID)
		if schoolID != "" {
			update.SchoolID = &schoolID
		}
	}
	if req.FirstName != nil {
		first := strings.TrimSpace(*req.FirstName)
		if first != "" {
			update.FirstName = &first
		}
	}
	if req.LastName != nil {
		last := strings.TrimSpace(*req.LastName)
		if last != "" {
			update.LastName = &last
		}
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		hash, err := crypto.HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "password_hash_failed")
			return
		}
		update.PasswordHash = &hash
	}

	user, err := s.store.UpdateUser(r.Context(), userID, update)
	if err != nil {
		writeError(w, http.StatusBadRequest, "update_failed")
		return
	}

	role, err := s.store.GetRole(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "role_not_found")
		return
	}

	summary := userSummary{
		ID:        user.ID,
		SchoolID:  user.SchoolID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserType:  role.UserType,
		AdminRole: role.AdminRole,
	}
	if role.UserType == "student" {
		if profile, err := s.store.GetStudentProfile(r.Context(), user.ID); err == nil {
			studentNumber := profile.StudentNumber
			summary.StudentNo = &studentNumber
		}
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "missing_user_id")
		return
	}

	deleted, err := s.store.DeleteUser(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "user_not_found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type createStudentRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	FirstName     string `json:"firstname"`
	LastName      string `json:"lastname"`
	CreatedOn     int64  `json:"createdOn"`
	StudentNumber int64  `json:"studentNumber"`
	SchoolID      string `json:"school"`
}

func (s *Server) handleCreateStudent(w http.ResponseWriter, r *http.Request) {
	var req createStudentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" || req.StudentNumber == 0 || req.SchoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if req.CreatedOn == 0 {
		writeError(w, http.StatusBadRequest, "missing_created_on")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	createdAt := time.Unix(req.CreatedOn, 0).UTC()

	user := model.User{
		ID:           uuid.NewString(),
		SchoolID:     req.SchoolID,
		Email:        req.Email,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    createdAt,
		UpdatedAt:    time.Now().UTC(),
	}
	studentNumber := strconv.FormatInt(req.StudentNumber, 10)
	if err := s.store.CreateUserWithRole(r.Context(), user, "student", nil, &studentNumber); err != nil {
		writeError(w, http.StatusBadRequest, "student_create_failed")
		return
	}

	writeJSON(w, http.StatusOK, studentSummary{
		ID:            user.ID,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		CreatedOn:     user.CreatedAt.Unix(),
		StudentNumber: req.StudentNumber,
		SchoolID:      user.SchoolID,
	})
}

func (s *Server) handleGetStudent(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	studentID := chi.URLParam(r, "studentId")
	if studentID == "" {
		writeError(w, http.StatusBadRequest, "missing_student_id")
		return
	}
	if claims.UserType == "student" && claims.UserID != studentID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	profile, err := s.store.GetStudentProfile(r.Context(), studentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "student_not_found")
		return
	}

	studentNumber, _ := strconv.ParseInt(profile.StudentNumber, 10, 64)
	include := r.URL.Query()["include"]
	includeGroups := contains(include, "groups")

	var groups *[]string
	if includeGroups {
		schoolID := ""
		if claims.UserType != "dev" {
			schoolID = claims.SchoolID
		}
		groupMap, err := s.fetchStudentGroups(r.Context(), []string{studentID}, schoolID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "groups_fetch_failed")
			return
		}
		groupIDs := groupMap[studentID]
		groups = &groupIDs
	}
	writeJSON(w, http.StatusOK, studentSummary{
		ID:            profile.User.ID,
		FirstName:     profile.User.FirstName,
		LastName:      profile.User.LastName,
		Email:         profile.User.Email,
		CreatedOn:     profile.User.CreatedAt.Unix(),
		StudentNumber: studentNumber,
		SchoolID:      profile.User.SchoolID,
		Groups:        groups,
	})
}

type patchStudentRequest struct {
	Email         *string `json:"email,omitempty"`
	Password      *string `json:"password,omitempty"`
	FirstName     *string `json:"firstname,omitempty"`
	LastName      *string `json:"lastname,omitempty"`
	SchoolID      *string `json:"school,omitempty"`
	StudentNumber *int64  `json:"studentNumber,omitempty"`
}

func (s *Server) handlePatchStudent(w http.ResponseWriter, r *http.Request) {
	studentID := chi.URLParam(r, "studentId")
	if studentID == "" {
		writeError(w, http.StatusBadRequest, "missing_student_id")
		return
	}

	var req patchStudentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	update := repository.UserUpdate{}
	if req.Email != nil {
		email := strings.TrimSpace(strings.ToLower(*req.Email))
		if email != "" {
			update.Email = &email
		}
	}
	if req.FirstName != nil {
		first := strings.TrimSpace(*req.FirstName)
		if first != "" {
			update.FirstName = &first
		}
	}
	if req.LastName != nil {
		last := strings.TrimSpace(*req.LastName)
		if last != "" {
			update.LastName = &last
		}
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		hash, err := crypto.HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "password_hash_failed")
			return
		}
		update.PasswordHash = &hash
	}
	if req.SchoolID != nil {
		school := strings.TrimSpace(*req.SchoolID)
		if school != "" {
			update.SchoolID = &school
		}
	}

	user, err := s.store.UpdateUser(r.Context(), studentID, update)
	if err != nil {
		writeError(w, http.StatusBadRequest, "update_failed")
		return
	}

	if req.StudentNumber != nil && *req.StudentNumber > 0 {
		if err := s.store.UpdateStudentNumber(r.Context(), studentID, strconv.FormatInt(*req.StudentNumber, 10)); err != nil {
			writeError(w, http.StatusInternalServerError, "update_failed")
			return
		}
	}

	profile, err := s.store.GetStudentProfile(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "student_not_found")
		return
	}

	studentNumber, _ := strconv.ParseInt(profile.StudentNumber, 10, 64)
	writeJSON(w, http.StatusOK, studentSummary{
		ID:            profile.User.ID,
		FirstName:     profile.User.FirstName,
		LastName:      profile.User.LastName,
		Email:         profile.User.Email,
		CreatedOn:     profile.User.CreatedAt.Unix(),
		StudentNumber: studentNumber,
		SchoolID:      profile.User.SchoolID,
	})
}

func (s *Server) handleDeleteStudent(w http.ResponseWriter, r *http.Request) {
	studentID := chi.URLParam(r, "studentId")
	if studentID == "" {
		writeError(w, http.StatusBadRequest, "missing_student_id")
		return
	}

	_, err := s.store.GetStudentProfile(r.Context(), studentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "student_not_found")
		return
	}

	deleted, err := s.store.DeleteUser(r.Context(), studentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "student_not_found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetStudentsBySchool(w http.ResponseWriter, r *http.Request) {
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	students, err := s.store.ListStudentsBySchool(r.Context(), schoolID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	include := r.URL.Query()["include"]
	includeGroups := contains(include, "groups")

	var groupMap map[string][]string
	if includeGroups {
		studentIDs := make([]string, 0, len(students))
		for _, student := range students {
			studentIDs = append(studentIDs, student.User.ID)
		}
		var err error
		groupMap, err = s.fetchStudentGroups(r.Context(), studentIDs, schoolID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "groups_fetch_failed")
			return
		}
	}

	resp := make([]studentSummary, 0, len(students))
	for _, student := range students {
		studentNumber, _ := strconv.ParseInt(student.StudentNumber, 10, 64)
		var groups *[]string
		if includeGroups {
			groupIDs := groupMap[student.User.ID]
			groups = &groupIDs
		}
		resp = append(resp, studentSummary{
			ID:            student.User.ID,
			FirstName:     student.User.FirstName,
			LastName:      student.User.LastName,
			Email:         student.User.Email,
			CreatedOn:     student.User.CreatedAt.Unix(),
			StudentNumber: studentNumber,
			Groups:        groups,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

type createTeacherRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	CreatedOn int64  `json:"createdOn"`
	SchoolID  string `json:"school"`
}

func (s *Server) handleCreateTeacher(w http.ResponseWriter, r *http.Request) {
	var req createTeacherRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" || req.SchoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if req.CreatedOn == 0 {
		writeError(w, http.StatusBadRequest, "missing_created_on")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	createdAt := time.Unix(req.CreatedOn, 0).UTC()

	user := model.User{
		ID:           uuid.NewString(),
		SchoolID:     req.SchoolID,
		Email:        req.Email,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    createdAt,
		UpdatedAt:    time.Now().UTC(),
	}

	if err := s.store.CreateUserWithRole(r.Context(), user, "teacher", nil, nil); err != nil {
		writeError(w, http.StatusBadRequest, "teacher_create_failed")
		return
	}

	writeJSON(w, http.StatusOK, teacherSummary{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedOn: user.CreatedAt.Unix(),
		SchoolID:  user.SchoolID,
	})
}

func (s *Server) handleGetTeacher(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}
	teacherID := chi.URLParam(r, "teacherId")
	if teacherID == "" {
		writeError(w, http.StatusBadRequest, "missing_teacher_id")
		return
	}
	if claims.UserType == "student" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if claims.UserType == "teacher" && claims.UserID != teacherID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	profile, err := s.store.GetTeacherProfile(r.Context(), teacherID)
	if err != nil {
		writeError(w, http.StatusNotFound, "teacher_not_found")
		return
	}

	writeJSON(w, http.StatusOK, teacherSummary{
		ID:        profile.User.ID,
		FirstName: profile.User.FirstName,
		LastName:  profile.User.LastName,
		Email:     profile.User.Email,
		CreatedOn: profile.User.CreatedAt.Unix(),
		SchoolID:  profile.User.SchoolID,
	})
}

type patchTeacherRequest struct {
	Email     *string `json:"email,omitempty"`
	Password  *string `json:"password,omitempty"`
	FirstName *string `json:"firstname,omitempty"`
	LastName  *string `json:"lastname,omitempty"`
	SchoolID  *string `json:"school,omitempty"`
}

func (s *Server) handlePatchTeacher(w http.ResponseWriter, r *http.Request) {
	teacherID := chi.URLParam(r, "teacherId")
	if teacherID == "" {
		writeError(w, http.StatusBadRequest, "missing_teacher_id")
		return
	}

	var req patchTeacherRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	update := repository.UserUpdate{}
	if req.Email != nil {
		email := strings.TrimSpace(strings.ToLower(*req.Email))
		if email != "" {
			update.Email = &email
		}
	}
	if req.FirstName != nil {
		first := strings.TrimSpace(*req.FirstName)
		if first != "" {
			update.FirstName = &first
		}
	}
	if req.LastName != nil {
		last := strings.TrimSpace(*req.LastName)
		if last != "" {
			update.LastName = &last
		}
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		hash, err := crypto.HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "password_hash_failed")
			return
		}
		update.PasswordHash = &hash
	}
	if req.SchoolID != nil {
		school := strings.TrimSpace(*req.SchoolID)
		if school != "" {
			update.SchoolID = &school
		}
	}

	user, err := s.store.UpdateUser(r.Context(), teacherID, update)
	if err != nil {
		writeError(w, http.StatusBadRequest, "update_failed")
		return
	}

	profile, err := s.store.GetTeacherProfile(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "teacher_not_found")
		return
	}

	writeJSON(w, http.StatusOK, teacherSummary{
		ID:        profile.User.ID,
		FirstName: profile.User.FirstName,
		LastName:  profile.User.LastName,
		Email:     profile.User.Email,
		CreatedOn: profile.User.CreatedAt.Unix(),
		SchoolID:  profile.User.SchoolID,
	})
}

func (s *Server) handleDeleteTeacher(w http.ResponseWriter, r *http.Request) {
	teacherID := chi.URLParam(r, "teacherId")
	if teacherID == "" {
		writeError(w, http.StatusBadRequest, "missing_teacher_id")
		return
	}

	_, err := s.store.GetTeacherProfile(r.Context(), teacherID)
	if err != nil {
		writeError(w, http.StatusNotFound, "teacher_not_found")
		return
	}

	deleted, err := s.store.DeleteUser(r.Context(), teacherID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "teacher_not_found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetTeachersBySchool(w http.ResponseWriter, r *http.Request) {
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	teachers, err := s.store.ListTeachersBySchool(r.Context(), schoolID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]teacherSummary, 0, len(teachers))
	for _, teacher := range teachers {
		resp = append(resp, teacherSummary{
			ID:        teacher.User.ID,
			FirstName: teacher.User.FirstName,
			LastName:  teacher.User.LastName,
			Email:     teacher.User.Email,
			CreatedOn: teacher.User.CreatedAt.Unix(),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

type createAdminRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	CreatedOn int64  `json:"createdOn"`
	Role      string `json:"role"`
	SchoolID  string `json:"school"`
}

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token")
		return
	}

	var req createAdminRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Role = strings.TrimSpace(strings.ToLower(req.Role))
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}
	if req.CreatedOn == 0 {
		writeError(w, http.StatusBadRequest, "missing_created_on")
		return
	}
	if !isValidAdminRole(req.Role) {
		writeError(w, http.StatusBadRequest, "invalid_admin_role")
		return
	}

	schoolID := strings.TrimSpace(req.SchoolID)
	if schoolID == "" {
		if claims.UserType == "admin" {
			schoolID = claims.SchoolID
		}
	}
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	createdAt := time.Unix(req.CreatedOn, 0).UTC()
	user := model.User{
		ID:           uuid.NewString(),
		SchoolID:     schoolID,
		Email:        req.Email,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    createdAt,
		UpdatedAt:    time.Now().UTC(),
	}

	role := req.Role
	if err := s.store.CreateUserWithRole(r.Context(), user, "admin", &role, nil); err != nil {
		writeError(w, http.StatusBadRequest, "admin_create_failed")
		return
	}

	writeJSON(w, http.StatusOK, adminSummary{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedOn: user.CreatedAt.Unix(),
		Role:      role,
		SchoolID:  user.SchoolID,
	})
}

func (s *Server) handleGetAdmin(w http.ResponseWriter, r *http.Request) {
	adminID := chi.URLParam(r, "adminId")
	if adminID == "" {
		writeError(w, http.StatusBadRequest, "missing_admin_id")
		return
	}

	profile, err := s.store.GetAdminProfile(r.Context(), adminID)
	if err != nil {
		writeError(w, http.StatusNotFound, "admin_not_found")
		return
	}

	writeJSON(w, http.StatusOK, adminSummary{
		ID:        profile.User.ID,
		FirstName: profile.User.FirstName,
		LastName:  profile.User.LastName,
		Email:     profile.User.Email,
		CreatedOn: profile.User.CreatedAt.Unix(),
		Role:      profile.Role,
		SchoolID:  profile.User.SchoolID,
	})
}

type patchAdminRequest struct {
	Email     *string `json:"email,omitempty"`
	Password  *string `json:"password,omitempty"`
	FirstName *string `json:"firstname,omitempty"`
	LastName  *string `json:"lastname,omitempty"`
	SchoolID  *string `json:"school,omitempty"`
	Role      *string `json:"role,omitempty"`
}

func (s *Server) handlePatchAdmin(w http.ResponseWriter, r *http.Request) {
	adminID := chi.URLParam(r, "adminId")
	if adminID == "" {
		writeError(w, http.StatusBadRequest, "missing_admin_id")
		return
	}

	var req patchAdminRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	update := repository.UserUpdate{}
	if req.Email != nil {
		email := strings.TrimSpace(strings.ToLower(*req.Email))
		if email != "" {
			update.Email = &email
		}
	}
	if req.FirstName != nil {
		first := strings.TrimSpace(*req.FirstName)
		if first != "" {
			update.FirstName = &first
		}
	}
	if req.LastName != nil {
		last := strings.TrimSpace(*req.LastName)
		if last != "" {
			update.LastName = &last
		}
	}
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		hash, err := crypto.HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "password_hash_failed")
			return
		}
		update.PasswordHash = &hash
	}
	if req.SchoolID != nil {
		school := strings.TrimSpace(*req.SchoolID)
		if school != "" {
			update.SchoolID = &school
		}
	}

	user, err := s.store.UpdateUser(r.Context(), adminID, update)
	if err != nil {
		writeError(w, http.StatusBadRequest, "update_failed")
		return
	}

	if req.Role != nil {
		role := strings.TrimSpace(strings.ToLower(*req.Role))
		if !isValidAdminRole(role) {
			writeError(w, http.StatusBadRequest, "invalid_admin_role")
			return
		}
		if err := s.store.UpdateAdminRole(r.Context(), adminID, role); err != nil {
			writeError(w, http.StatusInternalServerError, "update_failed")
			return
		}
	}

	profile, err := s.store.GetAdminProfile(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "admin_not_found")
		return
	}

	writeJSON(w, http.StatusOK, adminSummary{
		ID:        profile.User.ID,
		FirstName: profile.User.FirstName,
		LastName:  profile.User.LastName,
		Email:     profile.User.Email,
		CreatedOn: profile.User.CreatedAt.Unix(),
		Role:      profile.Role,
		SchoolID:  profile.User.SchoolID,
	})
}

func (s *Server) handleDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	adminID := chi.URLParam(r, "adminId")
	if adminID == "" {
		writeError(w, http.StatusBadRequest, "missing_admin_id")
		return
	}

	_, err := s.store.GetAdminProfile(r.Context(), adminID)
	if err != nil {
		writeError(w, http.StatusNotFound, "admin_not_found")
		return
	}

	deleted, err := s.store.DeleteUser(r.Context(), adminID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "admin_not_found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleGetAdminsBySchool(w http.ResponseWriter, r *http.Request) {
	schoolID := chi.URLParam(r, "schoolId")
	if schoolID == "" {
		writeError(w, http.StatusBadRequest, "missing_school_id")
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	admins, err := s.store.ListAdminsBySchool(r.Context(), schoolID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	resp := make([]adminSummary, 0, len(admins))
	for _, admin := range admins {
		resp = append(resp, adminSummary{
			ID:        admin.User.ID,
			FirstName: admin.User.FirstName,
			LastName:  admin.User.LastName,
			Email:     admin.User.Email,
			CreatedOn: admin.User.CreatedAt.Unix(),
			Role:      admin.Role,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) issueTokens(ctx context.Context, user model.User, role model.Role, userAgent, ip string) (string, string, error) {
	accessToken, err := auth.NewAccessToken(s.jwtPrivateKey, s.cfg.JWTIssuer, s.cfg.AccessTokenTTL, auth.Claims{
		UserID:    user.ID,
		UserType:  role.UserType,
		SchoolID:  user.SchoolID,
		AdminRole: role.AdminRole,
	})
	if err != nil {
		return "", "", err
	}

	refreshToken, err := crypto.NewRefreshToken()
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	session := model.RefreshSession{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: crypto.HashToken(refreshToken),
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	}
	if userAgent != "" {
		session.UserAgent = &userAgent
	}
	if ip != "" {
		session.IPAddress = &ip
	}

	if err := s.store.CreateRefreshSession(ctx, session); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
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

func (s *Server) requireAdminOrDev(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromContext(r.Context())
		if claims == nil || !isAdminOrDev(claims) {
			writeError(w, http.StatusForbidden, "admin_only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type claimsKey struct{}

func claimsFromContext(ctx context.Context) *auth.Claims {
	value := ctx.Value(claimsKey{})
	claims, _ := value.(*auth.Claims)
	return claims
}

func isAdminOrDev(claims *auth.Claims) bool {
	if claims == nil {
		return false
	}
	return claims.UserType == "admin" || claims.UserType == "dev"
}

func isValidAdminRole(role string) bool {
	switch strings.TrimSpace(strings.ToLower(role)) {
	case "planning", "absence", "manager":
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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

func (s *Server) fetchStudentGroups(ctx context.Context, studentIDs []string, schoolID string) (map[string][]string, error) {
	if s.academics == nil {
		return nil, errors.New("academics not configured")
	}
	if len(studentIDs) == 0 {
		return map[string][]string{}, nil
	}

	resp, err := s.academics.ListStudentGroupIds(ctx, &academicsv1.ListStudentGroupIdsRequest{
		StudentIds: studentIDs,
		SchoolId:   schoolID,
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(studentIDs))
	for _, entry := range resp.GetStudents() {
		result[entry.GetStudentId()] = append([]string{}, entry.GetGroupIds()...)
	}
	for _, studentID := range studentIDs {
		if _, ok := result[studentID]; !ok {
			result[studentID] = []string{}
		}
	}
	return result, nil
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.jwks)
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return ""
}
