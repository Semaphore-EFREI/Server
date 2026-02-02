# Repository Guidelines

## Project Structure & Module Organization
- `docs/` is the primary source of truth for the system design and APIs.
  - `docs/README.md`: documentation index with current sources of truth and archives.
  - `docs/Semaphore_Spec.md`: functional + technical specification and core workflows.
  - `docs/4-microservices-architecture-grpc.md`: service boundaries and gRPC contracts.
  - `docs/4-microservices-architecture_gateway.md`: Envoy edge responsibilities and public REST exposure.
  - `docs/openapi.json`: REST API contract (OpenAPI 3.0.4, canonical).
  - `docs/technical-stack.md`: proposed implementation stack and tooling.
  - `docs/ChartDB_per_service.json`: per-service database diagram export.
  - `docs/database-schema.md`: per-service database documentation and enums.
  - `docs/database-implementation.md`: migration and seed instructions for dev.
  - `docs/agent-context.md`: ops context for Envoy Gateway + mTLS.
  - `docs/archive/README.md`: historical planning/status docs (archived).
- `migrations/` stores per-service SQL migrations (schema + seed).
- `services/` contains implementation code, including `services/auth-identity`, `services/academics`, `services/attendance`, and `services/beacon`.

## Build, Test, and Development Commands
- Run a service locally from its directory (see service README files for env vars):
  - `go run ./cmd/server`
- Run tests for a service:
  - `go test ./...`
- Kubernetes commands must use the remote cluster config:
  - `KUBECONFIG=~/.kube/burrito-k3s.yaml kubectl ...`
  - Envoy gateway config is generated from `docker/envoy/envoy.yaml` via root kustomize; apply Istio with `KUBECONFIG=~/.kube/burrito-k3s.yaml kubectl apply -k .`

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
