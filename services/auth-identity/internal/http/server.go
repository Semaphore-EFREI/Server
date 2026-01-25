package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"semaphore/auth-identity/internal/auth"
	"semaphore/auth-identity/internal/config"
	"semaphore/auth-identity/internal/crypto"
	"semaphore/auth-identity/internal/model"
	"semaphore/auth-identity/internal/repository"
)

type Server struct {
	cfg   config.Config
	store *repository.Store
}

func NewServer(cfg config.Config, store *repository.Store) *Server {
	return &Server{cfg: cfg, store: store}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Post("/auth/login", s.handleLogin)
	r.Post("/auth/refresh", s.handleRefresh)
	r.Post("/auth/logout", s.handleLogout)

	r.With(s.authMiddleware).Post("/students/me/devices", s.handleRegisterDevice)

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
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	User         userSummary `json:"user"`
}

type userSummary struct {
	ID        string  `json:"id"`
	SchoolID  string  `json:"school_id"`
	Email     string  `json:"email"`
	FirstName string  `json:"first_name"`
	LastName  string  `json:"last_name"`
	UserType  string  `json:"user_type"`
	AdminRole *string `json:"admin_role,omitempty"`
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
	RefreshToken string `json:"refresh_token"`
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	_ = s.store.RevokeRefreshSession(r.Context(), session.ID, time.Now().UTC())
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type registerDeviceRequest struct {
	DeviceIdentifier string  `json:"device_identifier"`
	PublicKey        *string `json:"public_key"`
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

	now := time.Now().UTC()
	activeDevice, err := s.store.GetActiveDevice(r.Context(), claims.UserID)
	if err == nil {
		if activeDevice.DeviceIdentifier == req.DeviceIdentifier {
			_ = s.store.UpdateDeviceLastSeen(r.Context(), activeDevice.ID, now)
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		if activeDevice.RegisteredAt.After(now.Add(-s.cfg.DeviceRebindAfter)) {
			writeError(w, http.StatusConflict, "device_rebind_too_soon")
			return
		}
		if err := s.store.DeactivateDevices(r.Context(), claims.UserID, now); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	device := model.Device{
		ID:               uuid.NewString(),
		StudentID:        claims.UserID,
		DeviceIdentifier: req.DeviceIdentifier,
		PublicKey:        req.PublicKey,
		RegisteredAt:     now,
		LastSeenAt:       &now,
		Active:           true,
	}
	if err := s.store.CreateDevice(r.Context(), device); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
}

type createUserRequest struct {
	Email         string  `json:"email"`
	Password      string  `json:"password"`
	FirstName     string  `json:"first_name"`
	LastName      string  `json:"last_name"`
	SchoolID      string  `json:"school_id"`
	UserType      string  `json:"user_type"`
	AdminRole     *string `json:"admin_role,omitempty"`
	StudentNumber *string `json:"student_number,omitempty"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.UserType = strings.TrimSpace(strings.ToLower(req.UserType))
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
		summaries = append(summaries, userSummary{
			ID:        user.ID,
			SchoolID:  user.SchoolID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			UserType:  role.UserType,
			AdminRole: role.AdminRole,
		})
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

	writeJSON(w, http.StatusOK, userSummary{
		ID:        user.ID,
		SchoolID:  user.SchoolID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserType:  role.UserType,
		AdminRole: role.AdminRole,
	})
}

type updateUserRequest struct {
	Email     *string `json:"email,omitempty"`
	Password  *string `json:"password,omitempty"`
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	SchoolID  *string `json:"school_id,omitempty"`
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

	writeJSON(w, http.StatusOK, userSummary{
		ID:        user.ID,
		SchoolID:  user.SchoolID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		UserType:  role.UserType,
		AdminRole: role.AdminRole,
	})
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

func (s *Server) issueTokens(ctx context.Context, user model.User, role model.Role, userAgent, ip string) (string, string, error) {
	accessToken, err := auth.NewAccessToken(s.cfg.JWTSecret, s.cfg.JWTIssuer, s.cfg.AccessTokenTTL, auth.Claims{
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

		claims, err := auth.ParseToken(s.cfg.JWTSecret, token)
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
	case "super_admin", "school_admin":
		return true
	default:
		return false
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
