package repository

import (
	"context"
	"fmt"
	"strings"
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

func (s *Store) UserExists(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists)
	return exists, err
}

func (s *Store) CreateUserWithRole(ctx context.Context, user model.User, userType string, adminRole *string, studentNumber *string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	_, err = tx.Exec(ctx, `
    INSERT INTO users (id, school_id, email, password_hash, first_name, last_name, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
  `, user.ID, user.SchoolID, user.Email, user.PasswordHash, user.FirstName, user.LastName, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return err
	}

	switch userType {
	case "student":
		if studentNumber == nil || strings.TrimSpace(*studentNumber) == "" {
			return fmt.Errorf("student_number required")
		}
		_, err = tx.Exec(ctx, `INSERT INTO students (user_id, student_number, created_at) VALUES ($1, $2, $3)`, user.ID, strings.TrimSpace(*studentNumber), time.Now().UTC())
	case "teacher":
		_, err = tx.Exec(ctx, `INSERT INTO teachers (user_id, created_at) VALUES ($1, $2)`, user.ID, time.Now().UTC())
	case "admin":
		role := "manager"
		if adminRole != nil && strings.TrimSpace(*adminRole) != "" {
			role = strings.TrimSpace(*adminRole)
		}
		_, err = tx.Exec(ctx, `INSERT INTO administrators (user_id, role, created_at) VALUES ($1, $2, $3)`, user.ID, role, time.Now().UTC())
	case "dev":
		_, err = tx.Exec(ctx, `INSERT INTO developers (user_id, created_at) VALUES ($1, $2)`, user.ID, time.Now().UTC())
	default:
		return fmt.Errorf("unsupported user_type")
	}
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

type UserUpdate struct {
	Email        *string
	PasswordHash *string
	FirstName    *string
	LastName     *string
	SchoolID     *string
}

func (s *Store) UpdateUser(ctx context.Context, userID string, update UserUpdate) (model.User, error) {
	setParts := []string{}
	args := []interface{}{}
	idx := 1

	if update.Email != nil {
		setParts = append(setParts, fmt.Sprintf("email = $%d", idx))
		args = append(args, *update.Email)
		idx++
	}
	if update.PasswordHash != nil {
		setParts = append(setParts, fmt.Sprintf("password_hash = $%d", idx))
		args = append(args, *update.PasswordHash)
		idx++
	}
	if update.FirstName != nil {
		setParts = append(setParts, fmt.Sprintf("first_name = $%d", idx))
		args = append(args, *update.FirstName)
		idx++
	}
	if update.LastName != nil {
		setParts = append(setParts, fmt.Sprintf("last_name = $%d", idx))
		args = append(args, *update.LastName)
		idx++
	}
	if update.SchoolID != nil {
		setParts = append(setParts, fmt.Sprintf("school_id = $%d", idx))
		args = append(args, *update.SchoolID)
		idx++
	}

	if len(setParts) == 0 {
		return model.User{}, fmt.Errorf("no fields to update")
	}

	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", idx))
	args = append(args, time.Now().UTC())
	idx++

	args = append(args, userID)
	query := fmt.Sprintf(`
    UPDATE users
    SET %s
    WHERE id = $%d
    RETURNING id, school_id, email, password_hash, first_name, last_name, created_at, updated_at
  `, strings.Join(setParts, ", "), idx)

	var user model.User
	err := s.pool.QueryRow(ctx, query, args...).Scan(
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

func (s *Store) DeleteUser(ctx context.Context, userID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) ListUsers(ctx context.Context, limit int) ([]model.User, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
    SELECT id, school_id, email, password_hash, first_name, last_name, created_at, updated_at
    FROM users
    ORDER BY created_at DESC
    LIMIT $1
  `, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []model.User{}
	for rows.Next() {
		var user model.User
		if err := rows.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) GetStudentProfile(ctx context.Context, userID string) (model.StudentProfile, error) {
	var user model.User
	var studentNumber string
	row := s.pool.QueryRow(ctx, `
		SELECT u.id, u.school_id, u.email, u.password_hash, u.first_name, u.last_name, u.created_at, u.updated_at, s.student_number
		FROM users u
		INNER JOIN students s ON s.user_id = u.id
		WHERE u.id = $1
	`, userID)
	if err := row.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt, &studentNumber); err != nil {
		return model.StudentProfile{}, err
	}
	return model.StudentProfile{User: user, StudentNumber: studentNumber}, nil
}

func (s *Store) GetTeacherProfile(ctx context.Context, userID string) (model.TeacherProfile, error) {
	var user model.User
	row := s.pool.QueryRow(ctx, `
		SELECT u.id, u.school_id, u.email, u.password_hash, u.first_name, u.last_name, u.created_at, u.updated_at
		FROM users u
		INNER JOIN teachers t ON t.user_id = u.id
		WHERE u.id = $1
	`, userID)
	if err := row.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return model.TeacherProfile{}, err
	}
	return model.TeacherProfile{User: user}, nil
}

func (s *Store) ListStudentsBySchool(ctx context.Context, schoolID string, limit int) ([]model.StudentProfile, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.school_id, u.email, u.password_hash, u.first_name, u.last_name, u.created_at, u.updated_at, s.student_number
		FROM users u
		INNER JOIN students s ON s.user_id = u.id
		WHERE u.school_id = $1
		ORDER BY u.created_at DESC
		LIMIT $2
	`, schoolID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.StudentProfile
	for rows.Next() {
		var user model.User
		var studentNumber string
		if err := rows.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt, &studentNumber); err != nil {
			return nil, err
		}
		results = append(results, model.StudentProfile{User: user, StudentNumber: studentNumber})
	}
	return results, rows.Err()
}

func (s *Store) ListTeachersBySchool(ctx context.Context, schoolID string, limit int) ([]model.TeacherProfile, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.school_id, u.email, u.password_hash, u.first_name, u.last_name, u.created_at, u.updated_at
		FROM users u
		INNER JOIN teachers t ON t.user_id = u.id
		WHERE u.school_id = $1
		ORDER BY u.created_at DESC
		LIMIT $2
	`, schoolID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.TeacherProfile
	for rows.Next() {
		var user model.User
		if err := rows.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		results = append(results, model.TeacherProfile{User: user})
	}
	return results, rows.Err()
}

func (s *Store) UpdateStudentNumber(ctx context.Context, userID, studentNumber string) error {
	_, err := s.pool.Exec(ctx, `UPDATE students SET student_number = $1 WHERE user_id = $2`, studentNumber, userID)
	return err
}

func (s *Store) GetAdminProfile(ctx context.Context, userID string) (model.AdminProfile, error) {
	var user model.User
	var role string
	row := s.pool.QueryRow(ctx, `
		SELECT u.id, u.school_id, u.email, u.password_hash, u.first_name, u.last_name, u.created_at, u.updated_at, a.role
		FROM users u
		INNER JOIN administrators a ON a.user_id = u.id
		WHERE u.id = $1
	`, userID)
	if err := row.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt, &role); err != nil {
		return model.AdminProfile{}, err
	}
	return model.AdminProfile{User: user, Role: role}, nil
}

func (s *Store) ListAdminsBySchool(ctx context.Context, schoolID string, limit int) ([]model.AdminProfile, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.school_id, u.email, u.password_hash, u.first_name, u.last_name, u.created_at, u.updated_at, a.role
		FROM users u
		INNER JOIN administrators a ON a.user_id = u.id
		WHERE u.school_id = $1
		ORDER BY u.created_at DESC
		LIMIT $2
	`, schoolID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []model.AdminProfile
	for rows.Next() {
		var user model.User
		var role string
		if err := rows.Scan(&user.ID, &user.SchoolID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt, &role); err != nil {
			return nil, err
		}
		results = append(results, model.AdminProfile{User: user, Role: role})
	}
	return results, rows.Err()
}

func (s *Store) UpdateAdminRole(ctx context.Context, userID, role string) error {
	_, err := s.pool.Exec(ctx, `UPDATE administrators SET role = $1 WHERE user_id = $2`, role, userID)
	return err
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

func (s *Store) RevokeRefreshSessionsByUser(ctx context.Context, userID string, revokedAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
    UPDATE refresh_token_sessions
    SET revoked_at = $1
    WHERE user_id = $2 AND revoked_at IS NULL
  `, revokedAt, userID)
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
