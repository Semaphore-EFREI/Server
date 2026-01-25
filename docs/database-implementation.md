# Database Implementation Guide

This project uses **one Postgres instance** for development, with **one database per microservice**. Migrations are managed with **golang-migrate** and live under `migrations/`.

## Databases
Create four databases in the same Postgres instance:
- `auth_identity`
- `academics`
- `attendance`
- `beacon`

Each service owns its database; cross-service references are UUIDs only (no FK constraints).

## Migrations
Directory layout:
- `migrations/auth_identity`
- `migrations/academics`
- `migrations/attendance`
- `migrations/beacon`

Each directory includes:
- `0001_init.*.sql` for schema
- `0002_seed.*.sql` for dev seed data

## Running migrations (local)
Example commands (adjust host/user/password):
```
# Auth-identity
migrate -path migrations/auth_identity \
  -database "postgres://postgres:postgres@localhost:5432/auth_identity?sslmode=disable" up

# Academics
migrate -path migrations/academics \
  -database "postgres://postgres:postgres@localhost:5432/academics?sslmode=disable" up

# Attendance
migrate -path migrations/attendance \
  -database "postgres://postgres:postgres@localhost:5432/attendance?sslmode=disable" up

# Beacon
migrate -path migrations/beacon \
  -database "postgres://postgres:postgres@localhost:5432/beacon?sslmode=disable" up
```

## Seed data
Seed data is applied by the `0002_seed` migration in each service. IDs are fixed so demo entities line up across services (school, users, course, group, etc.).

If you want schema-only migrations for a clean environment, migrate to version 1:
```
migrate -path migrations/auth_identity \
  -database "postgres://.../auth_identity?sslmode=disable" -version 1
```

## Notes
- In production, you can move to one Postgres instance per service without changing migration structure.
- Enums are defined in the service DBs where they are used (e.g., `signature_method`, `signature_status` in `attendance`).
