# Auth-Identity Service

This service provides authentication, user management, refresh tokens, and student device binding for the Semaphore platform. It exposes REST endpoints for client apps and a gRPC identity query service for internal lookups.

## Responsibilities
- Login, refresh, logout (JWT + refresh tokens)
- User CRUD (admin/dev)
- Student/teacher endpoints aligned with OpenAPI spec
- Student device registration and rebind rules
- gRPC IdentityQueryService (user lite + existence checks)

## Local Run
Prerequisites:
- Postgres running (see repo `docker-compose.yml`)
- Migrations applied for `auth_identity`

Run:
```
cd services/auth-identity
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/auth_identity?sslmode=disable" \
JWT_SECRET="dev-secret" \
go run ./cmd/server
```

HTTP will listen on `:8081`, gRPC on `:9091`.

## REST Endpoints (selected)
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /students/me/devices`
- `GET /students/{schoolId}`
- `POST /student`
- `GET /student/{studentId}`
- `PATCH /student/{studentId}`
- `DELETE /student/{studentId}`
- `GET /teachers/{schoolId}`
- `POST /teacher`
- `GET /teacher/{teacherId}`
- `PATCH /teacher/{teacherId}`
- `DELETE /teacher/{teacherId}`
- `GET /admins/{schoolId}`
- `POST /admin`
- `GET /admin/{adminId}`
- `PATCH /admin/{adminId}`
- `DELETE /admin/{adminId}`
- `GET /users` (admin/dev)
- `POST /users` (admin/dev)
- `GET /users/{userId}`
- `PATCH /users/{userId}`
- `DELETE /users/{userId}`

See `docs/openapi.json` for full request/response shapes.

## gRPC
- `IdentityQueryService.GetUserLite`
- `IdentityQueryService.Exists`

Proto: `services/auth-identity/identity/v1/identity.proto`

## Tests
Set `AUTH_IDENTITY_TEST_DB` or `DATABASE_URL` to run HTTP endpoint tests:
```
AUTH_IDENTITY_TEST_DB="postgres://postgres:postgres@127.0.0.1:5432/auth_identity?sslmode=disable" \
go test ./...
```
