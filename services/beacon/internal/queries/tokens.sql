-- name: CreateBeaconToken :one
INSERT INTO beacon_tokens (
  id,
  beacon_id,
  token_hash,
  refresh_token_hash,
  created_at,
  expires_at,
  refresh_expires_at,
  revoked_at,
  last_used_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING id, beacon_id, token_hash, refresh_token_hash, created_at, expires_at, refresh_expires_at, revoked_at, last_used_at;

-- name: GetBeaconTokenByHash :one
SELECT id, beacon_id, token_hash, refresh_token_hash, created_at, expires_at, refresh_expires_at, revoked_at, last_used_at
FROM beacon_tokens
WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: GetBeaconTokenByRefresh :one
SELECT id, beacon_id, token_hash, refresh_token_hash, created_at, expires_at, refresh_expires_at, revoked_at, last_used_at
FROM beacon_tokens
WHERE refresh_token_hash = $1 AND revoked_at IS NULL;

-- name: RevokeBeaconToken :exec
UPDATE beacon_tokens
SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL;

-- name: TouchBeaconToken :exec
UPDATE beacon_tokens
SET last_used_at = $2
WHERE id = $1;
