# Kubernetes Worker Autoscaling (KEDA)

This manifest implements queue-depth autoscaling for separated Celery workers:

- `logs`
- `network`
- `memory`
- `rules`

## Prerequisites

1. Kubernetes cluster.
2. KEDA installed in cluster.
3. Redis service reachable from namespace `forensis`.
4. PostgreSQL service reachable from namespace `forensis`.

## Apply

```bash
kubectl apply -f deploy/k8s/workers-keda.yaml
```

## Notes

- Update image tag `ghcr.io/wahidhendrawan/forensis:latest` to your published release.
- Adjust Redis address in each `ScaledObject` trigger metadata if service name differs.
- `listLength` controls scaling sensitivity per queue.
- Recommended production pattern: keep `api-service` as separate deployment and only autoscale workers.
