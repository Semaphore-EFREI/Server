# Agent Context (Envoy gateway switch)

Last updated: 2026-01-29

## Goal
Switch from Istio IngressGateway to a standalone Envoy API gateway with Istio sidecar, keep Envoy config as single source of truth (`docker/envoy/envoy.yaml`), and keep Grafana panels working with Istio metrics.

## Current state (cluster)
- Envoy gateway deployed in `semaphore` namespace as `Deployment/envoy-gateway` with Istio sidecar injection enabled.
- Traefik (in `kube-system`) now routes `semaphore.deway.fr` to `Service/envoy-gateway` in `semaphore` (Terraform updated).
- Envoy admin Service exposed internally as `Service/envoy-gateway-admin` on port `9901`.
- Monitoring: `ServiceMonitor/envoy-gateway` scrapes `envoy-gateway-admin` `/stats/prometheus`.
- Grafana dashboard panel "Gateway Requests (RPS)" now targets `source_workload="envoy-gateway"` and namespace `semaphore`.

## Known issues / symptoms
- When strict mTLS is enabled, upstream calls from Envoy gateway fail with:
  - `503 upstream connect error or disconnect/reset before headers. reset reason: connection termination`
  - Service sidecars show `filter_chain_not_found` for connections from gateway pod IPs.
- This indicates the gateway’s outbound traffic is reaching services as **plaintext** (mTLS not applied), so strict mTLS rejects it.
- Temporary mitigations were applied to allow plaintext (PERMISSIVE) for gateway and services; RBAC was loosened to allow traffic.

## Likely root cause
- The Envoy gateway’s outbound traffic is **not being captured** by Istio iptables/sidecar, so mTLS upgrade does not happen.
- With strict mTLS, services reject plaintext, causing resets.

## Files changed (repo)
- `docker/envoy/envoy.yaml`
  - Kept as the single source of truth for Envoy config. (No health/root/forwarded headers added.)
- `k8s/istio/envoy-gateway.yaml`
  - Envoy gateway Deployment/Service/HPA + sidecar injection.
  - Admin service label `component: admin`.
- `k8s/istio/kustomization.yaml`
  - No longer includes namespace; includes envoy-gateway, mTLS/authz, observability.
- `kustomization.yaml` (repo root)
  - Includes `k8s/istio` and generates `envoy-gateway-config` from `docker/envoy/envoy.yaml`.
- `k8s/monitoring/envoy-gateway-servicemonitor.yaml`
  - Scrapes `envoy-gateway-admin` port `envoy-admin`.
- `k8s/monitoring/kustomization.yaml`
  - Replaced Istio ingress ServiceMonitor with Envoy gateway ServiceMonitor.
- `k8s/monitoring/dashboards/semaphore-dashboard.json`
  - Gateway panel now uses `source_workload="envoy-gateway"`, namespace `semaphore`.
- `k8s/istio/semaphore-mtls.yaml`
  - Added PERMISSIVE PeerAuthentication for `envoy-gateway` + each service (auth-identity, academics, attendance, beacon).
  - Added allow policy for gateway public traffic.
  - `allow-semaphore-namespace` policy currently allows **all** (no source constraints).
- `k8s/istio/semaphore-observability-authz.yaml`
  - Allows `/stats/prometheus` in addition to `/metrics`.
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
- Envoy admin `/clusters` shows endpoints healthy but `rq_error` increments.
- Service sidecar logs show `filter_chain_not_found` for gateway IPs (plaintext hitting strict mTLS).

## Next steps (for strict mTLS later)
- Ensure Envoy gateway outbound traffic is intercepted by the sidecar (validate by observing outbound stats in sidecar, or making sure iptables interception applies to Envoy’s egress).
- Remove PERMISSIVE policies once mTLS is confirmed end-to-end.
- Re-tighten AuthorizationPolicies to only allow expected sources (traefik/gateway principals) instead of `allow all`.

