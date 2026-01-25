# Semaphore Specs

This repository contains the specification package for Semaphore (a course attendance system). It is not an implementation yet—treat the contents as the source of truth for architecture, APIs, and domain rules, including Envoy for public REST exposure and gRPC for internal service calls.

## Contents
- `docs/Semaphore_Spec.md`: functional and technical specification.
- `docs/4-microservices-architecture-grpc.md`: service boundaries and gRPC contracts.
- `docs/4-microservices-architecture_gateway.md`: Envoy edge architecture and public REST routing.
- `docs/openapi.json`: REST API contract (OpenAPI 3.0.4).
- `docs/ChartDB.json`: database diagram export.
- `docs/technical-stack.md`: proposed implementation stack and tooling.

## Commands
No build, test, or runtime commands are defined yet. If you add executable code, document exact commands here and in `AGENTS.md`.

## Contributing
See `AGENTS.md` for repository guidelines, naming conventions, and PR expectations.
