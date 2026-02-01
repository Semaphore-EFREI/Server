# Agent Context (Envoy gateway switch)

Last updated: 2026-02-01

## Goal
Switch from Istio IngressGateway to a standalone Envoy API gateway with Istio sidecar, keep Envoy config as single source of truth (`docker/envoy/envoy.yaml`), and keep Grafana panels working with Istio metrics.

## Current state (cluster)
- Envoy gateway deployed in `semaphore` namespace as `Deployment/envoy-gateway` with Istio sidecar injection enabled.
- Traefik (in `kube-system`) now routes `semaphore.deway.fr` to `Service/envoy-gateway` in `semaphore` (Terraform updated).
- Envoy admin Service exposed internally as `Service/envoy-gateway-admin` on port `9901`.
- Monitoring: `ServiceMonitor/envoy-gateway` scrapes `envoy-gateway-admin` `/stats/prometheus`.
- Grafana dashboard panel "Gateway Requests (RPS)" now targets `source_workload="envoy-gateway"` and namespace `semaphore`.

## Known issues / symptoms
- Strict mTLS previously failed because the gateway’s outbound traffic was **plaintext** (no service identity match).
- Envoy sidecar logs showed **PassthroughCluster** for `/auth/login`, indicating outbound traffic did not resolve to a service identity.

## Likely root cause
- Envoy resolved short service names without namespace, and Istio DNS capture treated them as unknown hosts.
- That caused passthrough clusters instead of service-bound clusters, so mTLS was not applied.

## Files changed (repo)
- `docker/envoy/envoy.yaml`
  - Single source of truth for Envoy config; routes include `/auth/*`, `/users/*`, etc. `/auth/me` added.
  - Upstream clusters now use full service FQDNs to ensure Istio service identity matching.
- `k8s/istio/envoy-gateway.yaml`
  - Envoy gateway Deployment/Service/HPA + sidecar injection.
  - Admin service label `component: admin`.
  - Outbound capture annotation: `traffic.sidecar.istio.io/includeOutboundIPRanges: "*"`.
  - DNS capture annotations: `ISTIO_META_DNS_CAPTURE=true`, `ISTIO_META_DNS_AUTO_ALLOCATE=true` (via `proxy.istio.io/config`).
- `k8s/istio/kustomization.yaml`
  - No namespace; includes envoy-gateway, mTLS/authz, observability.
- `kustomization.yaml` (repo root)
  - Includes `k8s/istio` and generates `envoy-gateway-config` from `docker/envoy/envoy.yaml`.
- `k8s/monitoring/envoy-gateway-servicemonitor.yaml`
  - Scrapes `envoy-gateway-admin` port `envoy-admin`.
- `k8s/monitoring/kustomization.yaml`
  - Replaced Istio ingress ServiceMonitor with Envoy gateway ServiceMonitor.
- `k8s/monitoring/dashboards/semaphore-dashboard.json`
  - Gateway panel now uses `source_workload="envoy-gateway"`, namespace `semaphore`.
- `k8s/istio/semaphore-mtls.yaml`
  - Keeps namespace default **STRICT** mTLS and removes per-service PERMISSIVE exceptions (except postgres).
  - Added allow policy for gateway public traffic.
  - `allow-semaphore-namespace` policy currently allows **all** (no source constraints).
- `k8s/istio/semaphore-observability-authz.yaml`
  - Allows `/stats/prometheus` in addition to `/metrics`.
- `services/auth-identity/internal/http/server.go`
  - Added `GET /auth/me` handler (returns current user summary based on JWT claims).
- `services/auth-identity/internal/http/server_test.go`
  - Added `/auth/me` test.
- `services/auth-identity/README.md`
  - Lists `/auth/me`.
- Removed:
  - `k8s/istio/semaphore-gateway.yaml`
  - `k8s/istio/semaphore-ingress-auth.yaml`
  - `k8s/monitoring/istio-ingress-servicemonitor.yaml`

## Terraform changes
- `infra/terraform/main.tf`
  - Traefik Ingress resources moved to `semaphore` namespace.
  - Backend service changed from `istio-ingressgateway` to `envoy-gateway`.

## Important commands / reminders
- **Always** use:
  - `KUBECONFIG=~/.kube/burrito-k3s.yaml kubectl ...`
- Apply stack + istio via root kustomize:
  - `KUBECONFIG=~/.kube/burrito-k3s.yaml kubectl apply -k .`
- Apply monitoring:
  - `KUBECONFIG=~/.kube/burrito-k3s.yaml kubectl apply -k k8s/monitoring`

## Debug evidence (from cluster)
- Envoy gateway pods are 2/2 with sidecar.
- Envoy admin `/clusters` shows endpoints healthy but `rq_error` increments when strict mTLS is on.
- Service sidecar logs show `filter_chain_not_found` for gateway IPs under strict mTLS.
- Gateway sidecar logs show `PassthroughCluster` for `/auth/login`, indicating service identity not matched.

## Next steps
- Re-test with strict mTLS enabled and confirm gateway sidecar logs use `outbound|8081||auth-identity.semaphore.svc.cluster.local`.
- Tighten AuthorizationPolicies to only allow expected sources once stable.
