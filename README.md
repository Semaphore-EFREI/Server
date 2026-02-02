# Semaphore

This repository contains the specification package **and** the Go microservice implementations for Semaphore (course attendance system). Use the docs as the source of truth for architecture, APIs, and domain rules (Envoy for public REST exposure, gRPC for internal service calls), then align code to the contracts.

## Contents
- `docs/README.md`: documentation index with current source-of-truth references and archives.
- `docs/Semaphore_Spec.md`: functional and technical specification.
- `docs/openapi.json`: REST API contract (OpenAPI 3.0.4, canonical).
- `docs/4-microservices-architecture-grpc.md`: service boundaries and gRPC contracts.
- `docs/4-microservices-architecture_gateway.md`: Envoy edge architecture and public REST routing.
- `docs/database-schema.md`: per-service database documentation and enums.
- `docs/database-implementation.md`: migration and seed instructions for dev.
- `docs/ChartDB_per_service.json`: per-service database diagram export.
- `docs/technical-stack.md`: proposed implementation stack and tooling.
- `docs/agent-context.md`: ops context for Envoy Gateway + mTLS.
- `docs/archive/README.md`: historical planning/status docs.
- `migrations/`: per-service SQL migrations (schema + seed).
- `services/auth-identity`: auth-identity microservice (Go).
- `services/academics`: academics microservice (Go).
- `services/attendance`: attendance microservice (Go).
- `services/beacon`: beacon microservice (Go).
- `docker/`: container images and Envoy assets.
- `k8s/`: Kubernetes manifests (Istio, gateway, monitoring).

## Documentation
Start with `docs/README.md` for a guided map of specs, architecture notes, and data-model references.

## Auth-Identity Service
The first microservice is implemented in `services/auth-identity`. It provides JWT auth, refresh tokens, user CRUD, student/teacher endpoints aligned with OpenAPI, device binding, and a gRPC IdentityQueryService for internal lookups. See `services/auth-identity/README.md` for usage.

## Academics Service
The academics microservice is implemented in `services/academics`. It handles schools, preferences, classrooms, courses, student groups, and assignments, plus the gRPC AcademicsQueryService. See `services/academics/README.md` for usage.

## Attendance Service
The attendance microservice is implemented in `services/attendance`. It owns signatures and the gRPC AttendanceCommandService for beacon submissions. See `services/attendance/README.md` for usage.

## Beacon Service
The beacon microservice is implemented in `services/beacon`. It issues opaque beacon tokens, manages beacons, and submits validated beacon proofs to attendance via gRPC. See `services/beacon/README.md` for usage.

## Commands
- Run a service locally from its directory (see service README files for env vars):
  - `go run ./cmd/server`
- Run tests for a service:
  - `go test ./...`

## TODO
- Decide and enforce a single TOTP secret encoding (base32/base64/hex) for beacon NFC validation.

## Contributing
See `AGENTS.md` for repository guidelines, naming conventions, and PR expectations.
