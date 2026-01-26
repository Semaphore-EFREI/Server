# Attendance Service

This service is the source of truth for attendance signatures. It exposes REST endpoints aligned with `docs/openapi.json` and a gRPC command API for beacon submissions. It validates courses and relationships via academics (gRPC) and device binding via auth-identity (gRPC).

## Responsibilities
- Signature creation, update, and soft delete
- Attendance rule enforcement (time window, closing delay, signatureClosed)
- gRPC `AttendanceCommandService` for beacon submissions

## Local Run
Prerequisites:
- Postgres running (see repo `docker-compose.yml`)
- Migrations applied for `attendance`
- gRPC dependencies running: auth-identity (`:9091`), academics (`:9092`)

Run:
```
cd services/attendance
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/attendance?sslmode=disable" \
JWT_PUBLIC_KEY_FILE="/path/to/public.pem" \
JWT_ISSUER="semaphore-auth-identity" \
ACADEMICS_GRPC_ADDR="127.0.0.1:9092" \
IDENTITY_GRPC_ADDR="127.0.0.1:9091" \
REDIS_ADDR="127.0.0.1:6379" \
REDIS_PASSWORD="your_redis_password" \
BUZZLIGHTYEAR_TTL="45s" \
go run ./cmd/server
```

HTTP listens on `:8083`, gRPC on `:9093`.

## REST Endpoints
- `POST /signature`
- `GET /signature/{signatureId}`
- `PATCH /signature/{signatureId}`
- `DELETE /signature/{signatureId}`
- `GET /signatures`
- `GET /signatures/report`

### Reporting
- `GET /signatures?courseId=...` returns student + teacher signatures for the course.
- `GET /signatures?studentId=...` or `teacherId=...` lists signatures for that user (admin/dev only).
- `GET /signatures/report?courseId=...` returns counts per status and total teacher signatures.

### Device binding
Student signature creation requires `X-Device-ID` to match the active student device in auth-identity.

## gRPC
- `AttendanceCommandService.CreateSignatureAttempt`

Proto: `services/attendance/attendance/v1/attendance.proto`
