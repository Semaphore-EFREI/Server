# Strict mTLS Playbook (Envoy Gateway + Istio)

Last updated: 2026-02-04

## Summary
Strict mTLS in the `semaphore` namespace fails if Envoy Gateway routes to **pod IPs** instead of **service VIPs**. Istio only applies `ISTIO_MUTUAL` when the outbound cluster is built from service DNS/VIP, so pod-IP routing falls back to `PassthroughCluster` and the backend sidecars reject plaintext.

## Incident Snapshot
- **Time:** Wed, 04 Feb 2026 02:52:57 GMT
- **Symptom:** 503 between Envoy Gateway and `auth-identity` when `PeerAuthentication` was STRICT.
- **Backend logs:** `filter_chain_not_found` (plaintext to a strict TLS listener).

## Required Conditions For Strict mTLS
- Envoy Gateway **data-plane** pods run with Istio sidecar injection.
- Gateway outbound traffic targets **service DNS/VIP**, not pod IPs.
- A `DestinationRule` with `ISTIO_MUTUAL` exists for `*.semaphore.svc.cluster.local` in the gateway sidecar’s scope.

## Strict mTLS Solution (Target State)
- Keep `PeerAuthentication` `STRICT` at namespace level in `semaphore`.
- Force Envoy Gateway to **route to Services**, not endpoints.
- Verify the gateway sidecar uses `ISTIO_MUTUAL` for service clusters before removing any permissive overrides.

## Temporary Fallback (If Strict Breaks)
- Use per-service `PeerAuthentication` `PERMISSIVE` only for the impacted backends.
- Remove the overrides once service-VIP routing is confirmed.

## Verification Checklist
- Gateway sidecar clusters show `ISTIO_MUTUAL` for `*.semaphore.svc.cluster.local`.
- No `PassthroughCluster` entries for backend traffic in gateway sidecar logs.
- `/auth/login` and `/courses` return 200 with namespace `STRICT` and no PERMISSIVE overrides.

## Files In This Repo
- `k8s/istio/semaphore-mtls.yaml`
- `k8s/istio/envoy-gateway.yaml`
- `docs/agent-context.md` (update when strict is validated end-to-end)
