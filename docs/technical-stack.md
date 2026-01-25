# Technical Stack & Tooling (Proposed)

This document captures the technical solutions discussed so far. It is a working proposal and can evolve as implementation begins.

## Languages & Runtimes
- **Go (Golang)**: Primary language for microservices. Chosen for gRPC support, strong concurrency, and simple deployment.

## API & Service Communication
- **Public APIs:** HTTP REST (JSON) exposed through Envoy.
- **Internal APIs:** gRPC only between microservices.
- **Envoy Gateway:** Single public entry point; handles TLS termination, routing, auth verification at the edge, and observability concerns.

## Database
- **PostgreSQL:** Primary data store for all services. Selected for ACID guarantees and strong relational modeling.

## Data Access Layer
- **SQLC:** SQL-first, type-safe query generation for Go. Fast to iterate without ORM magic.

## Migrations
- **Migration tooling (TBD):** Use the explicit migration tool golang-migrate to keep schema changes versioned.

## Infrastructure & Deployment (Later Phase)
- **Kubernetes:** Target deployment platform for services.
- **Terraform:** Infrastructure-as-code for cluster resources and managed dependencies.

## Observability & Operations (Later Phase)
- **Structured logging:** Use standard JSON logs for ingestion.
- **Tracing/metrics:** OpenTelemetry recommended for distributed tracing and service metrics.

## References
- gRPC contracts and service boundaries: `docs/4-microservices-architecture-grpc.md`.
- Gateway responsibilities and routing: `docs/4-microservices-architecture_gateway.md`.
