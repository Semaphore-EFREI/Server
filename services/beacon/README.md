# Beacon Service

This service manages beacon provisioning, beacon authentication, and validated beacon submissions to attendance via gRPC. It owns beacon keys and opaque beacon tokens; attendance still enforces business rules.

## Responsibilities
- Beacon CRUD (dev-only endpoints)
- Beacon authentication (opaque access + refresh tokens)
- BuzzLightyear proof validation and submission to attendance (gRPC)
- Classroom assignment for beacons

## Local Run
Prerequisites:
- Postgres running (see repo `docker-compose.yml`)
- Migrations applied for `beacon`
- Attendance gRPC running (`:9093`)

Run:
```
cd services/beacon
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/beacon?sslmode=disable" \
ATTENDANCE_GRPC_ADDR="127.0.0.1:9093" \
JWT_PUBLIC_KEY_FILE="/path/to/public.pem" \
JWT_ISSUER="semaphore-auth-identity" \
go run ./cmd/server
```

HTTP listens on `:8084`.

## REST Endpoints
Beacon auth:
- `POST /beacon/auth/token`
- `POST /beacon/auth/refreshToken`

Beacon actions:
- `POST /beacon/buzzLightyear`
- `PATCH /beacon/{beaconId}` (update `totpKey`)

Dev management:
- `GET /dev/beacons`
- `POST /dev/beacon`
- `GET /dev/beacon/{beaconId}`
- `PATCH /dev/beacon/{beaconId}`
- `DELETE /dev/beacon/{beaconId}`
- `POST /dev/beacon/{beaconId}/classroom`
- `DELETE /dev/beacon/{beaconId}/classroom/{classroomId}`

Dev endpoints require an auth-identity JWT (`user_type=dev`), with admin also allowed for classroom assignment endpoints.

## Beacon BuzzLightyear Notes
- Requires `Authorization: Bearer <opaque-token>`
- Requires `Idempotency-Key` header
- Requires `X-Student-ID` and `X-Course-ID` headers (used to call attendance gRPC)
- The proof payload is currently a generated 32-bit random code (hardware integration TBD)

## Auth Notes
- Beacon access/refresh tokens are opaque random strings stored as hashes in Postgres.
- Timestamp validation window is controlled via `BEACON_AUTH_WINDOW`.
- ECDSA signature verification is currently stubbed (presence + timestamp window only).

Proto used: `services/attendance/attendance/v1/attendance.proto` (CreateSignatureAttempt).
