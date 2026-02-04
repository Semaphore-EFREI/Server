# Documentation

This folder contains the source-of-truth specifications, contracts, and architecture notes for Semaphore. Start here to understand the system before changing code or adding services.

## Specifications & contracts (source of truth)
- `Semaphore_Spec.md`: functional + technical spec (roles, rules, business constraints).
- `openapi.json`: public REST contract served via Envoy (canonical).
- `4-microservices-architecture-grpc.md`: internal gRPC boundaries and required contracts.
- `4-microservices-architecture_gateway.md`: Envoy edge responsibilities and routing model.
- `signature-challenge-flow.md`: student signature challenge + device verification flow.

## Data model
- `ChartDB_per_service.json`: ChartDB export for per-service schemas.
- `database-schema.md`: per-service DB documentation, enums, and table descriptions.
- `database-implementation.md`: migrations + seed strategy for local dev.

## Implementation choices
- `technical-stack.md`: recommended stack and tooling (Go + Postgres + sqlc + migrations).

## Operations & infra notes
- `agent-context.md`: Envoy Gateway + mTLS operational context (k8s + Terraform notes).
- `mtls-strict-playbook.md`: strict mTLS troubleshooting + checklist for Envoy Gateway.

## Archive (historical planning/status)
- `archive/README.md`: index of archived docs.


# Plan
Add a concise “Strict mTLS solution plan” section that documents how Envoy Gateway should use TLS to backends
(service VIP routing + mTLS policy) and how to validate it, then update doc links if needed.

## Scope
- In: Update docs/mtls-strict-playbook.md with a step-by-step plan, include validation/rollback steps and
references to k8s/istio/envoy-gateway.yaml and k8s/istio/semaphore-mtls.yaml.
- Out: Making live cluster changes.

## Action items
[ ] Review docs/mtls-strict-playbook.md to locate the right insertion point for a “Plan” section.
[ ] Confirm the intended backend TLS mechanism to document (Envoy Gateway BackendTrafficPolicy vs Gateway API
BackendTLSPolicy vs Istio DestinationRule only).
[ ] Add a “Plan” section detailing: enable strict, force service VIP routing, apply backend TLS policy, remove
PERMISSIVE overrides.
[ ] Add a validation checklist: confirm ISTIO_MUTUAL clusters, no PassthroughCluster, verify /auth/login and /
courses with strict.
[ ] Add a rollback note: reapply per-service PeerAuthentication PERMISSIVE if strict breaks.
[ ] Update docs/README.md if a new subsection or doc link needs to be surfaced.
[ ] Optional: add a short “Evidence/Logs to capture” bullet list for future incidents.

## Open questions
- Which resource should be authoritative for “backend TLS” in this cluster: Envoy Gateway BackendTrafficPolicy,
Gateway API BackendTLSPolicy, or Istio DestinationRule only?
- Do you want the plan in docs/mtls-strict-playbook.md or docs/agent-context.md (or both)?