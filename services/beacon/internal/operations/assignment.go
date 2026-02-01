package operations

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"semaphore/beacon/internal/db"
)

const (
	ErrInvalidBeaconID          = "invalid_beacon_id"
	ErrMissingClassroomID       = "missing_classroom_id"
	ErrInvalidClassroomID       = "invalid_classroom_id"
	ErrBeaconNotFound           = "beacon_not_found"
	ErrClassroomAlreadyAssigned = "classroom_already_assigned"
	ErrClassroomNotAssigned     = "classroom_not_assigned"
	ErrServerError              = "server_error"
)

type Error struct {
	Code string
}

func (e *Error) Error() string {
	return e.Code
}

func AssignBeaconToClassroom(ctx context.Context, store *db.Store, beaconID, classroomID string) error {
	beaconUUID, err := uuid.Parse(beaconID)
	if err != nil {
		return &Error{Code: ErrInvalidBeaconID}
	}
	if classroomID == "" {
		return &Error{Code: ErrMissingClassroomID}
	}
	classroomUUID, err := uuid.Parse(classroomID)
	if err != nil {
		return &Error{Code: ErrInvalidClassroomID}
	}

	beacon, err := store.Queries.GetBeacon(ctx, pgUUID(beaconUUID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &Error{Code: ErrBeaconNotFound}
		}
		return &Error{Code: ErrServerError}
	}

	if beacon.ClassroomID.Valid {
		current := uuidString(beacon.ClassroomID)
		if current != classroomUUID.String() {
			return &Error{Code: ErrClassroomAlreadyAssigned}
		}
		return nil
	}

	if err := store.Queries.UpdateBeaconClassroom(ctx, db.UpdateBeaconClassroomParams{
		ID:          pgUUID(beaconUUID),
		ClassroomID: pgUUID(classroomUUID),
		UpdatedAt:   pgTime(time.Now().UTC()),
	}); err != nil {
		return &Error{Code: ErrServerError}
	}
	return nil
}

func RemoveBeaconFromClassroom(ctx context.Context, store *db.Store, beaconID, classroomID string) error {
	beaconUUID, err := uuid.Parse(beaconID)
	if err != nil {
		return &Error{Code: ErrInvalidBeaconID}
	}
	if classroomID == "" {
		return &Error{Code: ErrMissingClassroomID}
	}
	if _, err := uuid.Parse(classroomID); err != nil {
		return &Error{Code: ErrInvalidClassroomID}
	}

	beacon, err := store.Queries.GetBeacon(ctx, pgUUID(beaconUUID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &Error{Code: ErrBeaconNotFound}
		}
		return &Error{Code: ErrServerError}
	}
	if !beacon.ClassroomID.Valid || uuidString(beacon.ClassroomID) != classroomID {
		return &Error{Code: ErrClassroomNotAssigned}
	}

	if err := store.Queries.ClearBeaconClassroom(ctx, db.ClearBeaconClassroomParams{
		ID:        pgUUID(beaconUUID),
		UpdatedAt: pgTime(time.Now().UTC()),
	}); err != nil {
		return &Error{Code: ErrServerError}
	}
	return nil
}

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

func uuidString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}
