# Beacon Service

This service manages beacon provisioning and classroom assignment. It owns beacon keys and exposes admin/dev HTTP management endpoints plus internal gRPC APIs.

## Responsibilities
- Beacon CRUD (dev-only create/update/delete; admin can read)
- Classroom assignment for beacons
- Internal gRPC query/command APIs for other services

## Local Run
Prerequisites:
- Postgres running (see repo `docker-compose.yml`)
- Migrations applied for `beacon`

Run:
```
cd services/beacon
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/beacon?sslmode=disable" \
JWT_PUBLIC_KEY_FILE="/path/to/public.pem" \
JWT_ISSUER="semaphore-auth-identity" \
SERVICE_AUTH_TOKEN="dev-service-token" \
REDIS_ADDR="127.0.0.1:6379" \
REDIS_PASSWORD="your_redis_password" \
BUZZLIGHTYEAR_PROOF_TTL="90s" \
go run ./cmd/server
```

HTTP listens on `:8084`.

## Configuration
- `SERVICE_AUTH_TOKEN`: shared token required for internal gRPC calls.
- `JWT_PUBLIC_KEY`/`JWT_PUBLIC_KEY_FILE`: public key for validating admin/dev JWTs.
- `JWT_ISSUER`: expected JWT issuer.
- `REDIS_ADDR`: Redis address for BuzzLightyear replay protection.
- `REDIS_PASSWORD`: Redis password, if required.
- `BUZZLIGHTYEAR_PROOF_TTL`: replay cache TTL (duration or `_SECONDS`). Defaults to 90s.

## REST Endpoints
Admin/dev:
- `GET /beacons`
- `GET /beacon/{beaconId}`
- `POST /beacon/{beaconId}/classroom`
- `DELETE /beacon/{beaconId}/classroom/{classroomId}`

Dev-only:
- `POST /beacon`
- `PATCH /beacon/{beaconId}`
- `DELETE /beacon/{beaconId}`

All endpoints require an auth-identity JWT. Admins are allowed to read and manage classroom assignments; only devs can create/update/delete beacons.
