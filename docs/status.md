# Project Status (2026-02-01)

## Summary
Semaphore now has three implemented microservices (auth-identity, academics, attendance) with Postgres migrations, REST endpoints per OpenAPI, and gRPC contracts for internal calls. Beacon and gateway remain unimplemented. Core documentation and database specs are in `docs/`.

## Implemented Services
- **auth-identity**: JWT auth, refresh tokens, user CRUD, role management, student device binding, gRPC identity queries (incl. device validation).
- **academics**: schools/preferences, classrooms, courses, student groups, assignments; gRPC AcademicsQueryService + AcademicsCommandService (CloseExpiredCourses).
- **attendance**: signature CRUD with soft delete, attendance rules (time window + closing delay), device binding validation (sync gRPC to auth-identity), gRPC AttendanceCommandService; signature close job (configurable).

## Data & Migrations
- Per-service schema migrations in `migrations/` with seed data for dev.
- Attendance schema includes soft delete and extended enums aligned with OpenAPI.
- Academics courses support `signature_closed_override` for manual reopen behavior.

## Tests & Coverage (unit focus)
- Some unit tests exist (JWT, crypto, HTTP integration tests behind `INTEGRATION_TESTS=1`).
- Coverage is still low in most packages; unit tests are being added to improve baseline coverage without requiring DBs.

## Known Gaps
- **Beacon service** not implemented.
- **Envoy gateway** config not implemented (spec-only).
- Attendance rules missing: teacher presence gating, enforcement of school preference method flags, open/close signing endpoints.
- Cross-service expansion fields still stubbed (students/signatures/beacons enrichment).

## Next Recommended Steps
1. Implement missing attendance rules and add list/report endpoints for signatures.
2. Build the beacon microservice and wire beacon → attendance gRPC.
3. Add Envoy gateway config and public routing.
4. Expand automated tests (unit + integration).
