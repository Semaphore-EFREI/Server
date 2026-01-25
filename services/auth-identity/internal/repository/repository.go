package repository

import (
  "context"
  "time"

  "github.com/jackc/pgx/v5"
  "github.com/jackc/pgx/v5/pgxpool"

  "semaphore/auth-identity/internal/model"
)

type Store struct {
  pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
  return &Store{pool: pool}
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
  var user model.User
  row := s.pool.QueryRow(ctx, `
    SELECT id, school_id, email, password_hash, first_name, last_name, created_at, updated_at
    FROM users
    WHERE email = $1
  `, email)
  err := row.Scan(
    &user.ID,
    &user.SchoolID,
    &user.Email,
    &user.PasswordHash,
    &user.FirstName,
    &user.LastName,
    &user.CreatedAt,
    &user.UpdatedAt,
  )
  return user, err
}

func (s *Store) GetUserByID(ctx context.Context, userID string) (model.User, error) {
  var user model.User
  row := s.pool.QueryRow(ctx, `
    SELECT id, school_id, email, password_hash, first_name, last_name, created_at, updated_at
    FROM users
    WHERE id = $1
  `, userID)
  err := row.Scan(
    &user.ID,
    &user.SchoolID,
    &user.Email,
    &user.PasswordHash,
    &user.FirstName,
    &user.LastName,
    &user.CreatedAt,
    &user.UpdatedAt,
  )
  return user, err
}

func (s *Store) GetRole(ctx context.Context, userID string) (model.Role, error) {
  role := model.Role{UserID: userID}

  if exists(ctx, s.pool, `SELECT 1 FROM students WHERE user_id = $1`, userID) {
    role.UserType = "student"
    return role, nil
  }
  if exists(ctx, s.pool, `SELECT 1 FROM teachers WHERE user_id = $1`, userID) {
    role.UserType = "teacher"
    return role, nil
  }
  var adminRole string
  row := s.pool.QueryRow(ctx, `SELECT role FROM administrators WHERE user_id = $1`, userID)
  if err := row.Scan(&adminRole); err == nil {
    role.UserType = "admin"
    role.AdminRole = &adminRole
    return role, nil
  }
  if exists(ctx, s.pool, `SELECT 1 FROM developers WHERE user_id = $1`, userID) {
    role.UserType = "dev"
    return role, nil
  }
  return role, pgx.ErrNoRows
}

func (s *Store) CreateRefreshSession(ctx context.Context, session model.RefreshSession) error {
  _, err := s.pool.Exec(ctx, `
    INSERT INTO refresh_token_sessions (id, user_id, token_hash, created_at, expires_at, revoked_at, user_agent, ip_address)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
  `, session.ID, session.UserID, session.TokenHash, session.CreatedAt, session.ExpiresAt, session.RevokedAt, session.UserAgent, session.IPAddress)
  return err
}

func (s *Store) GetRefreshSession(ctx context.Context, tokenHash string) (model.RefreshSession, error) {
  var session model.RefreshSession
  row := s.pool.QueryRow(ctx, `
    SELECT id, user_id, token_hash, created_at, expires_at, revoked_at, user_agent, ip_address
    FROM refresh_token_sessions
    WHERE token_hash = $1
  `, tokenHash)
  err := row.Scan(&session.ID, &session.UserID, &session.TokenHash, &session.CreatedAt, &session.ExpiresAt, &session.RevokedAt, &session.UserAgent, &session.IPAddress)
  return session, err
}

func (s *Store) RevokeRefreshSession(ctx context.Context, sessionID string, revokedAt time.Time) error {
  _, err := s.pool.Exec(ctx, `UPDATE refresh_token_sessions SET revoked_at = $1 WHERE id = $2`, revokedAt, sessionID)
  return err
}

func (s *Store) GetActiveDevice(ctx context.Context, studentID string) (model.Device, error) {
  var device model.Device
  row := s.pool.QueryRow(ctx, `
    SELECT id, student_id, device_identifier, public_key, registered_at, last_seen_at, revoked_at, active
    FROM student_devices
    WHERE student_id = $1 AND active = true
  `, studentID)
  err := row.Scan(&device.ID, &device.StudentID, &device.DeviceIdentifier, &device.PublicKey, &device.RegisteredAt, &device.LastSeenAt, &device.RevokedAt, &device.Active)
  return device, err
}

func (s *Store) DeactivateDevices(ctx context.Context, studentID string, revokedAt time.Time) error {
  _, err := s.pool.Exec(ctx, `
    UPDATE student_devices
    SET active = false, revoked_at = $1
    WHERE student_id = $2 AND active = true
  `, revokedAt, studentID)
  return err
}

func (s *Store) CreateDevice(ctx context.Context, device model.Device) error {
  _, err := s.pool.Exec(ctx, `
    INSERT INTO student_devices (id, student_id, device_identifier, public_key, registered_at, last_seen_at, revoked_at, active)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
  `, device.ID, device.StudentID, device.DeviceIdentifier, device.PublicKey, device.RegisteredAt, device.LastSeenAt, device.RevokedAt, device.Active)
  return err
}

func (s *Store) UpdateDeviceLastSeen(ctx context.Context, deviceID string, seenAt time.Time) error {
  _, err := s.pool.Exec(ctx, `
    UPDATE student_devices
    SET last_seen_at = $1
    WHERE id = $2
  `, seenAt, deviceID)
  return err
}

func exists(ctx context.Context, pool *pgxpool.Pool, query string, arg string) bool {
  var exists bool
  _ = pool.QueryRow(ctx, `SELECT EXISTS (`+query+`)`, arg).Scan(&exists)
  return exists
}
