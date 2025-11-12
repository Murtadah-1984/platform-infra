# 🔍 Jaeger Distributed Tracing Setup

## Overview

Jaeger has been added to the shared cluster infrastructure for distributed tracing across all microservices.

## Configuration

### Deployment Location

- **Namespace**: `monitoring`
- **Chart**: `jaegertracing/jaeger`
- **Version**: 0.99.0
- **Mode**: All-in-one (simplified deployment)

### Services

Jaeger exposes the following services:

- **jaeger-agent** (`jaeger-agent.monitoring.svc.cluster.local:6831`) - UDP agent for receiving traces
- **jaeger-collector** (`jaeger-collector.monitoring.svc.cluster.local`) - HTTP/gRPC collector
  - Port 14268 (HTTP)
  - Port 14250 (gRPC)
  - Port 9411 (Zipkin-compatible endpoint)
- **jaeger-query** (`jaeger-query.monitoring.svc.cluster.local:16686`) - UI and query API

### Storage

- **Type**: Badger (file-based, suitable for small to medium clusters)
- **Retention**: 7 days (168 hours)
- **Storage**: 20Gi persistent volume
- **Storage Class**: Managed Premium (Azure)

### Resources

- **Memory**: 512Mi-1Gi
- **CPU**: 500m-1000m

## Accessing Jaeger UI

### Port Forward (Development)

```bash
kubectl port-forward -n monitoring svc/jaeger-query 16686:16686
```

Then access: `http://localhost:16686`

### LoadBalancer (Production)

To expose Jaeger UI externally, update `charts/monitoring/templates/jaeger-values.yaml`:

```yaml
query:
  service:
    type: LoadBalancer
```

## Integration with Services

### Payment Service

The Payment service is already configured to use shared Jaeger:

**Environment Variables** (in `charts/services/payment/values.yaml`):
```yaml
- name: OpenTelemetry__Jaeger__Host
  value: "jaeger-agent.monitoring.svc.cluster.local"
- name: OpenTelemetry__Jaeger__Port
  value: "6831"
- name: OpenTelemetry__Zipkin__Endpoint
  value: "http://jaeger-collector.monitoring.svc.cluster.local:9411/api/v2/spans"
```

### Other Services

To add Jaeger to other services, add similar environment variables:

```yaml
env:
  - name: OpenTelemetry__Jaeger__Host
    value: "jaeger-agent.monitoring.svc.cluster.local"
  - name: OpenTelemetry__Jaeger__Port
    value: "6831"
```

## Grafana Integration

Jaeger is configured as a data source in Grafana:

- **Name**: Jaeger
- **URL**: `http://jaeger-query.monitoring.svc.cluster.local:16686`
- **Type**: Jaeger

You can now:
- View traces in Grafana
- Correlate traces with logs (Loki) and metrics (Prometheus)
- Use trace-to-logs linking

## Network Policies

Network policies allow services in `platform` and `infrastructure` namespaces to send traces to Jaeger:

- UDP port 6831 (agent)
- TCP port 14268 (collector HTTP)
- TCP port 14250 (collector gRPC)
- TCP port 9411 (Zipkin endpoint)

## Verification

### Check Jaeger Deployment

```bash
# Check pods
kubectl get pods -n monitoring -l app=jaeger

# Check services
kubectl get svc -n monitoring | grep jaeger

# Check logs
kubectl logs -n monitoring -l app=jaeger --tail=50
```

### Test Trace Collection

1. Make a request to Payment service
2. Check Jaeger UI for traces
3. Verify spans are being collected

## Production Considerations

### Storage Backend

For production at scale, consider switching from Badger to:

- **Elasticsearch** - Better for large-scale deployments
- **Cassandra** - High availability and scalability

Update `charts/monitoring/templates/jaeger-values.yaml`:

```yaml
provisionDataStore:
  elasticsearch: true  # or cassandra: true

storage:
  type: elasticsearch  # or cassandra
  elasticsearch:
    serverUrls: "http://elasticsearch:9200"
```

### High Availability

For HA, switch from all-in-one to production deployment:

```yaml
allInOne:
  enabled: false

collector:
  enabled: true
  replicas: 3

query:
  enabled: true
  replicas: 2

ingester:
  enabled: true
  replicas: 2
```

## Troubleshooting

### Traces Not Appearing

1. Check service can reach Jaeger:
   ```bash
   kubectl exec -it <payment-pod> -- nc -zv jaeger-agent.monitoring.svc.cluster.local 6831
   ```

2. Check OpenTelemetry configuration in service
3. Verify network policies allow egress to monitoring namespace
4. Check Jaeger logs for errors

### High Memory Usage

- Reduce retention period (currently 7 days)
- Increase memory limits
- Consider switching to Elasticsearch backend

## Related Documentation

- [Observability Setup](./OBSERVABILITY_SETUP.md)
- [Payment Integration Guide](./PAYMENT_INTEGRATION.md)
- [Deployment Summary](./DEPLOYMENT_SUMMARY.md)

