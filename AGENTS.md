# Repository Guidelines

## Project Structure & Module Organization
- `docs/` is the primary source of truth for the system design and APIs.
  - `docs/Semaphore_Spec.md`: functional + technical specification and core workflows.
  - `docs/4-microservices-architecture-grpc.md`: service boundaries and gRPC contracts.
  - `docs/4-microservices-architecture_gateway.md`: Envoy edge responsibilities and public REST exposure.
  - `docs/openapi.json`: REST API contract (OpenAPI 3.0.4).
  - `docs/technical-stack.md`: proposed implementation stack and tooling.
  - `docs/ChartDB_per_service.json`: per-service database diagram export.
  - `docs/database-schema.md`: per-service database documentation and enums.
  - `docs/database-implementation.md`: migration and seed instructions for dev.
- `migrations/` stores per-service SQL migrations (schema + seed).
- `services/` contains implementation code, starting with `services/auth-identity` and `services/academics`.
- There is no application source code in this repo yet; treat it as a specification package.

## Build, Test, and Development Commands
- No build, test, or runtime commands are defined yet.
- If you add executable code, document the exact commands here (and in `README.md`) with examples.

## Coding Style & Naming Conventions
- Keep Markdown concise with clear headings and short bullet lists.
- Preserve naming used in the specs:
  - Service names are kebab-case (e.g., `auth-identity`, `attendance`).
  - gRPC/proto fields are snake_case (e.g., `school_id`).
  - OpenAPI JSON fields are camelCase where already used (e.g., `beaconId`).
- Keep Envoy/public REST and internal gRPC statements consistent across gateway and gRPC docs.
- Maintain existing JSON formatting (2-space indentation).

## Testing Guidelines
- No automated test framework is defined yet.
- When code is introduced, add unit/integration tests alongside it and update this section with the framework and commands.

## Commit & Pull Request Guidelines
- Git history currently uses short, imperative messages (e.g., “Semaphore backend init”). Keep new commits concise and action-oriented.
- PRs should include:
  - A short summary and scope of changes.
  - Links to related issues/spec sections.
  - Updates to `docs/openapi.json` or architecture docs if APIs/service boundaries change.

## Security & Configuration Notes
- Do not commit secrets or real credentials in specs or examples.
- If you change API base URLs or authentication flows in `docs/openapi.json`, call it out explicitly in the PR description.
