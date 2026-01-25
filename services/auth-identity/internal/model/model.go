package model

import "time"

type User struct {
	ID           string
	SchoolID     string
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Role struct {
	UserID    string
	UserType  string
	AdminRole *string
}

type RefreshSession struct {
	ID        string
	UserID    string
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	UserAgent *string
	IPAddress *string
}

type Device struct {
	ID               string
	StudentID        string
	DeviceIdentifier string
	PublicKey        *string
	RegisteredAt     time.Time
	LastSeenAt       *time.Time
	RevokedAt        *time.Time
	Active           bool
}
