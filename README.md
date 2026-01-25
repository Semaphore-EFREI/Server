# Semaphore Specs

This repository contains the specification package for Semaphore (a course attendance system). It is not an implementation yet—treat the contents as the source of truth for architecture, APIs, and domain rules, including Envoy for public REST exposure and gRPC for internal service calls.

## Contents
- `docs/Semaphore_Spec.md`: functional and technical specification.
- `docs/4-microservices-architecture-grpc.md`: service boundaries and gRPC contracts.
- `docs/4-microservices-architecture_gateway.md`: Envoy edge architecture and public REST routing.
- `docs/openapi.json`: REST API contract (OpenAPI 3.0.4).
- `docs/technical-stack.md`: proposed implementation stack and tooling.
- `docs/ChartDB_per_service.json`: per-service database diagram export.
- `docs/database-schema.md`: per-service database documentation and enums.
- `docs/database-implementation.md`: migration and seed instructions for dev.
- `migrations/`: per-service SQL migrations (schema + seed).
- `services/auth-identity`: first microservice implementation (Go).
- `services/academics`: academics microservice implementation (Go).

## Auth-Identity Service
The first microservice is implemented in `services/auth-identity`. It provides JWT auth, refresh tokens, user CRUD, student/teacher endpoints aligned with OpenAPI, device binding, and a gRPC IdentityQueryService for internal lookups. See `services/auth-identity/README.md` for usage.

## Academics Service
The academics microservice is implemented in `services/academics`. It handles schools, preferences, classrooms, courses, student groups, and assignments, plus the gRPC AcademicsQueryService. See `services/academics/README.md` for usage.

## Commands
No build, test, or runtime commands are defined yet. If you add executable code, document exact commands here and in `AGENTS.md`.

## Contributing
See `AGENTS.md` for repository guidelines, naming conventions, and PR expectations.
