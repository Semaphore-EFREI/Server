package grpc

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func parseUUID(value string) (pgtype.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
}

func uuidString(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}
	return uuid.UUID(value.Bytes).String()
}

func requireUUID(value string, field string) (pgtype.UUID, error) {
	parsed, err := parseUUID(value)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid %s", field)
	}
	return parsed, nil
}
