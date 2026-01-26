-- name: GetBeaconIdempotency :one
SELECT id, beacon_id, key, endpoint, response_status, response_body, created_at
FROM beacon_idempotency_keys
WHERE beacon_id = $1 AND key = $2 AND endpoint = $3;

-- name: CreateBeaconIdempotency :exec
INSERT INTO beacon_idempotency_keys (
  id,
  beacon_id,
  key,
  endpoint,
  response_status,
  response_body,
  created_at
) VALUES (
  $1, $2, $3, $4, $5, $6, $7
);
