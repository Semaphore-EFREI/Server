# Agent Context (Envoy Gateway + mTLS)

Last updated: 2026-02-01

## Goal
Replace the legacy static Envoy gateway with Envoy Gateway (Gateway API) while keeping Istio mTLS for internal traffic and allowing plaintext ingress from Traefik for now.

## Current State (Cluster)
- Envoy Gateway control plane runs in `envoy-gateway-system` (no sidecar).
- Envoy Gateway data plane runs as `Deployment/envoy-semaphore-gateway` with Istio sidecar and inbound capture enabled.
- Gateway resources (GatewayClass/Gateway/HTTPRoutes/SecurityPolicies) live in `semaphore`.
- Traefik routes `semaphore.deway.fr` to `Service/envoy-semaphore-gateway` in `envoy-gateway-system` (plaintext).
- Internal traffic from gateway to services uses mTLS (namespace `semaphore` is STRICT).
- In-mesh callers to the gateway use mTLS (`DestinationRule` with `ISTIO_MUTUAL`).

## Changes Applied (Repo)
### Envoy Gateway (Gateway API)
- `k8s/istio/envoy-gateway.yaml`
  - EnvoyProxy with stable deployment name `envoy-semaphore-gateway`.
  - GatewayClass + Gateway + HTTPRoutes for auth/academics/attendance/beacon.
  - SecurityPolicies for JWT (public + protected routes).
  - DestinationRule `envoy-gateway-mtls` for `*.envoy-gateway-system.svc.cluster.local`.
  - Service `envoy-semaphore-gateway` (port 80 -> targetPort 10080).
  - HPA for the gateway (min 2 / max 5 / CPU 70%).

### Monitoring
- `k8s/monitoring/envoy-gateway-servicemonitor.yaml`
  - Switched from ServiceMonitor to PodMonitor for Envoy Gateway data-plane pods.
- `k8s/monitoring/dashboards/semaphore-dashboard.json`
  - Gateway RPS panel now targets `source_canonical_service="envoy"` in `envoy-gateway-system`.

### HPA for Services
- `k8s/semaphore-stack.yaml`
  - Added CPU/memory requests for `auth-identity`, `academics`, `attendance`, `beacon`.
  - Added HPAs:
    - auth-identity: min 2 / max 5 / CPU 70%
    - academics: min 2 / max 5 / CPU 70%
    - attendance: min 2 / max 8 / CPU 70%
    - beacon: min 2 / max 4 / CPU 70%
  - Scale behavior: +100%/30s up, -30%/60s down, 5 min down-stabilization.

### Terraform (Traefik → Envoy Gateway)
- `infra/terraform/variables.tf`
  - Added `envoy_gateway_namespace` (default `envoy-gateway-system`).
  - Added `envoy_gateway_chart_version` (default `v0.0.0-latest`).
  - Added frontend job variables (repo URL, branch, job name).
- `infra/terraform/main.tf`
  - Ingress resources moved to `envoy-gateway-system`.
  - Backend service updated to `envoy-semaphore-gateway`.
  - Creates `envoy-gateway-system` namespace.
  - Installs Envoy Gateway via Helm (`eg` release).

### Jenkins
- `infra/terraform/jenkins.tf`
  - Added `semaphore_frontend` job (builds Vue/Vite app into `semaphore-frontend` image).
- `infra/terraform/jenkins-pipeline-frontend.xml`
  - Inline pipeline to build/push frontend image and roll out `deployment/frontend`.

## Operational Notes
- Apply gateway resources:
  - `kubectl apply -f k8s/istio/envoy-gateway.yaml`
- Apply monitoring:
  - `kubectl apply -k k8s/monitoring`
- Terraform apply updates Traefik ingress routing.
  - Use `-var` with `cat` to preserve PEM newlines:
```bash
cd infra/terraform
terraform apply \
  -var "semaphore_jwt_private_key=$(cat jwt-private-key.pem)" \
  -var "semaphore_jwt_public_key=$(cat jwt-public-key.pem)" \
  -var "semaphore_jwt_issuer=semaphore-auth-identity"
```

## Known Constraints
- Traefik → Gateway is plaintext until Traefik is placed in the mesh or the Gateway listener is configured for mTLS/TLS.
