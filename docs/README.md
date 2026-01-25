# Documentation

This folder contains the source-of-truth specifications, contracts, and architecture notes for Semaphore. Start here to understand the system before changing code or adding services.

## Core specs
- `Semaphore_Spec.md`: functional + technical spec (roles, rules, business constraints).
- `openapi.json`: public REST contract served via Envoy.
- `4-microservices-architecture-grpc.md`: internal gRPC boundaries and required contracts.
- `4-microservices-architecture_gateway.md`: Envoy edge responsibilities and routing model.

## Data model
- `ChartDB_per_service.json`: ChartDB export for per-service schemas.
- `database-schema.md`: per-service DB documentation, enums, and table descriptions.
- `database-implementation.md`: migrations + seed strategy for local dev.

## Implementation choices
- `technical-stack.md`: recommended stack and tooling (Go + Postgres + sqlc + migrations).
