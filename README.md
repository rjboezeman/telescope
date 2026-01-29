# Telescope

A Cilium network policy violation monitor that connects to Hubble Relay and streams dropped flows as JSON.

Telescope provides real-time visibility into network policy denials across your Kubernetes cluster, helping you debug connectivity issues and validate your NetworkPolicy configurations.

## Features

- Real-time streaming of policy-denied flows from Hubble Relay
- JSON output for easy integration with logging systems (Fluentd, Loki, etc.)
- Automatic reconnection with exponential backoff
- Namespace filtering or cluster-wide monitoring
- TLS support with configurable certificate verification
- Detailed flow information including source/destination IPs, ports, and pod labels

## Requirements

- Kubernetes cluster with Cilium CNI
- Hubble enabled with Hubble Relay deployed
- Network access to Hubble Relay service

## Installation

### Building from source

```bash
go build -o telescope .
```

### Container image

```bash
docker build -t telescope:latest .
```

## Usage

```bash
telescope [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--hubble-endpoint` | `hubble-relay.kube-system.svc.cluster.local:443` | Hubble Relay endpoint |
| `--tls` | `true` | Enable TLS connection |
| `--tls-skip-verify` | `true` | Skip TLS certificate verification |
| `--namespace` | `""` (all) | Monitor specific namespace (empty for all namespaces) |
| `--since` | `1h` | Monitor flows since this duration ago |
| `--verbose` | `false` | Enable verbose logging with additional flow details |

### Examples

Monitor all namespaces with default settings:

```bash
telescope
```

Monitor a specific namespace:

```bash
telescope --namespace=production
```

Connect to Hubble Relay without TLS:

```bash
telescope --tls=false --hubble-endpoint=hubble-relay.kube-system.svc.cluster.local:80
```

Monitor with verbose output:

```bash
telescope --verbose --since=30m
```

## Output Format

Telescope outputs one JSON object per line for each policy violation:

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event_type": "type:1  sub_type:133",
  "node_name": "worker-node-01",
  "source": {
    "namespace": "default",
    "pod_name": "client-pod-abc123",
    "labels": [
      "k8s:app=client",
      "k8s:io.kubernetes.pod.namespace=default"
    ],
    "id": 1234,
    "ip": "10.0.1.15"
  },
  "destination": {
    "namespace": "backend",
    "pod_name": "api-server-xyz789",
    "labels": [
      "k8s:app=api-server",
      "k8s:io.kubernetes.pod.namespace=backend"
    ],
    "id": 5678,
    "ip": "10.0.2.42"
  },
  "protocol": {
    "type": "TCP",
    "source_port": 45678,
    "destination_port": 8080
  },
  "policy_info": "Drop reason: POLICY_DENIED",
  "drop_reason": "POLICY_DENIED",
  "summary": "TCP Flags: SYN",
  "verdict": "DROPPED"
}
```

With `--verbose`, additional flow details are included:

```json
{
  "...": "...",
  "flow_details": {
    "ethernet_source": "aa:bb:cc:dd:ee:ff",
    "ethernet_destination": "11:22:33:44:55:66",
    "ip_source": "10.0.1.15",
    "ip_destination": "10.0.2.42"
  }
}
```

## Kubernetes Deployment

### Basic deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: telescope
  namespace: telescope
spec:
  replicas: 1
  selector:
    matchLabels:
      app: telescope
  template:
    metadata:
      labels:
        app: telescope
    spec:
      containers:
      - name: telescope
        image: your-registry/telescope:latest
        args:
          - "--hubble-endpoint=hubble-relay.kube-system.svc.cluster.local:443"
          - "--tls=true"
          - "--tls-skip-verify=true"
          - "--since=1h"
          - "--verbose=false"
```

### Ansible deployment

An Ansible role is available for deploying Telescope with configurable variables:

```yaml
# Variables
telescope_hubble_endpoint: "hubble-relay.kube-system.svc.cluster.local"
telescope_tls_enabled: true
telescope_tls_skip_verify: true
telescope_since: "1h"
telescope_verbose: false
```

The port is automatically set to 443 when TLS is enabled, or 80 when disabled.

## Integration with Logging Systems

Telescope outputs JSON to stdout, making it easy to integrate with various logging solutions.

### Fluentd

Configure Fluentd to parse JSON logs from the Telescope container:

```xml
<source>
  @type tail
  path /var/log/containers/telescope*.log
  pos_file /var/log/fluentd-telescope.pos
  tag telescope
  <parse>
    @type json
  </parse>
</source>
```

### Loki with Promtail

```yaml
scrape_configs:
  - job_name: telescope
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: telescope
        action: keep
    pipeline_stages:
      - json:
          expressions:
            timestamp: timestamp
            source_namespace: source.namespace
            destination_namespace: destination.namespace
            drop_reason: drop_reason
```

## Troubleshooting

### Connection refused

Ensure Hubble Relay is running and accessible:

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=hubble-relay
kubectl get svc -n kube-system hubble-relay
```

### TLS errors

If you encounter TLS certificate errors, either:
- Use `--tls-skip-verify=true` (default)
- Configure proper TLS certificates for Hubble Relay

### No flows received

Verify Hubble is enabled and observing flows:

```bash
hubble observe --verdict DROPPED
```

Check that Cilium agents are healthy:

```bash
cilium status
```

## License

MIT