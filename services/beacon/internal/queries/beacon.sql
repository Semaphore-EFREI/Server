-- name: CreateBeacon :one
INSERT INTO beacons (
  serial_number,
  signature_key,
  totp_key,
  classroom_id,
  program_version,
  created_at,
  updated_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7
)
RETURNING id, serial_number, signature_key, totp_key, classroom_id, program_version, created_at, updated_at, last_seen_at, deleted_at;

-- name: GetBeacon :one
SELECT id, serial_number, signature_key, totp_key, classroom_id, program_version, created_at, updated_at, last_seen_at, deleted_at
FROM beacons
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetBeaconBySerial :one
SELECT id, serial_number, signature_key, totp_key, classroom_id, program_version, created_at, updated_at, last_seen_at, deleted_at
FROM beacons
WHERE serial_number = $1 AND deleted_at IS NULL;

-- name: ListBeacons :many
SELECT id, serial_number, signature_key, totp_key, classroom_id, program_version, created_at, updated_at, last_seen_at, deleted_at
FROM beacons
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1;

-- name: UpdateBeacon :one
UPDATE beacons
SET serial_number = COALESCE($2, serial_number),
    totp_key = COALESCE($3, totp_key),
    classroom_id = COALESCE($4, classroom_id),
    program_version = COALESCE($5, program_version),
    updated_at = $6
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, serial_number, signature_key, totp_key, classroom_id, program_version, created_at, updated_at, last_seen_at, deleted_at;

-- name: DeleteBeacon :exec
UPDATE beacons
SET deleted_at = $2,
    updated_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateBeaconClassroom :exec
UPDATE beacons
SET classroom_id = $2,
    updated_at = $3
WHERE id = $1 AND deleted_at IS NULL;

-- name: ClearBeaconClassroom :exec
UPDATE beacons
SET classroom_id = NULL,
    updated_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateBeaconTOTP :exec
UPDATE beacons
SET totp_key = $2,
    updated_at = $3
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateBeaconLastSeen :exec
UPDATE beacons
SET last_seen_at = $2
WHERE id = $1 AND deleted_at IS NULL;
