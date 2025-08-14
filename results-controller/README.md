# StackRox Results Controller

The StackRox Results Controller exposes StackRox security results (vulnerabilities and policy violations) as Kubernetes Custom Resources, enabling Kubernetes RBAC-based access to security data.

## Overview

This controller creates namespace-scoped `StackRoxResults` Custom Resources that contain:
- **Vulnerabilities**: CVE information for container images in the namespace
- **Policy Violations**: Active security policy alerts for workloads in the namespace  
- **Summary Statistics**: Counts by severity level
- **Sync Status**: Last update time and synchronization status

## Features

- ✅ **Kubernetes RBAC Integration**: Use standard Kubernetes permissions to control access
- ✅ **Namespace-Scoped**: Each namespace gets its own results CR for fine-grained access
- ✅ **Read-Only Results**: Status-only CRs prevent accidental modification of security data
- ✅ **OCP Console Ready**: CRs are designed for consumption by OpenShift Console plugins
- ✅ **Scalable Design**: Built-in pagination and result limits prevent etcd overload
- ✅ **Machine-to-Machine Auth**: Uses service account tokens for secure Central API access
- ✅ **Periodic Sync**: Configurable sync intervals (default: 5 minutes)

## Architecture

The controller follows the standard Kubernetes controller pattern:

```
┌─────────────┐    M2M Auth     ┌─────────────┐
│   Results   │◄──────────────► │   Central   │
│ Controller  │   (SA Token)    │     API     │
└─────────────┘                 └─────────────┘
       │
       │ Creates/Updates
       ▼
┌─────────────────────────────────────────────┐
│        StackRoxResults CRs                  │
│  ┌─────────────┐ ┌─────────────┐           │
│  │ Namespace A │ │ Namespace B │    ...    │
│  │   Results   │ │   Results   │           │
│  └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Kubernetes cluster with StackRox Central deployed
- Central configured to accept M2M authentication from the controller's service account
- Cluster admin permissions for initial deployment

### Deploy the Controller

1. Install the CRD:
```bash
kubectl apply -f config/crd/bases/platform.stackrox.io_stackroxresults.yaml
```

2. Deploy the controller:
```bash
kubectl apply -k config/default
```

3. Verify deployment:
```bash
kubectl get deployment -n stackrox results-controller-controller-manager
kubectl get stackroxresults -A
```

## Usage

### Viewing Results

List all StackRoxResults:
```bash
kubectl get stackroxresults -A
```

View results for a specific namespace:
```bash
kubectl get stackroxresults stackrox-results -n my-namespace -o yaml
```

View summary information:
```bash
kubectl get stackroxresults -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,\
VULNERABILITIES:.status.totalVulnerabilities,\
VIOLATIONS:.status.totalPolicyViolations,\
STATUS:.status.syncStatus,\
LAST_SYNC:.status.lastSyncTime"
```

### Understanding the Data

#### Vulnerabilities
Each vulnerability includes:
- CVE identifier and CVSS score
- Severity level (Low, Medium, High, Critical)
- Whether it's fixable and fix version
- Affected images and deployments in the namespace

#### Policy Violations  
Each violation includes:
- Alert ID and policy name
- Severity and violation state
- Resource that triggered the violation
- Remediation guidance

#### Summary Statistics
The status includes summary counts by severity:
```yaml
status:
  vulnerabilitySummary:
    Critical: 2
    High: 15
    Medium: 8
    Low: 3
  policyViolationSummary:
    High: 5
    Medium: 2
```

### RBAC Configuration

#### Namespace Developers
Grant namespace developers read access to their results:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developers-view-security-results
  namespace: my-namespace
subjects:
- kind: User
  name: developer@company.com
roleRef:
  kind: ClusterRole
  name: stackroxresults-viewer-role
  apiGroup: rbac.authorization.k8s.io
```

#### Security Team
Grant security team cluster-wide read access:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-team-view-all-results
subjects:
- kind: Group
  name: security-team
roleRef:
  kind: ClusterRole
  name: stackroxresults-viewer-role
  apiGroup: rbac.authorization.k8s.io
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SYNC_INTERVAL_MINUTES` | `5` | How often to sync data from Central |

### Resource Limits

The controller enforces these limits to prevent etcd overload:
- **Vulnerabilities**: Maximum 100 per namespace CR
- **Policy Violations**: Maximum 50 per namespace CR

If a namespace exceeds these limits, the most severe results are included and totals are shown in summary fields.

## Monitoring

### Controller Health

Check controller status:
```bash
kubectl get pods -n stackrox -l control-plane=controller-manager
kubectl logs -n stackrox -l control-plane=controller-manager
```

### Sync Status

Monitor sync health across namespaces:
```bash
kubectl get stackroxresults -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,\
STATUS:.status.syncStatus,\
MESSAGE:.status.syncMessage,\
LAST_SYNC:.status.lastSyncTime"
```

### Metrics

The controller exposes Prometheus metrics on `:8443/metrics`:
- Sync duration and success rates
- Resource counts per namespace
- Error rates and retry attempts

## Troubleshooting

### Common Issues

#### Authentication Failures
```bash
# Check service account token
kubectl get secret -n stackrox | grep results-controller
kubectl describe pod -n stackrox -l control-plane=controller-manager

# Verify Central M2M configuration
# Ensure Central is configured to trust the controller's service account
```

#### Sync Failures
```bash
# Check controller logs
kubectl logs -n stackrox -l control-plane=controller-manager --tail=100

# Verify Central connectivity
kubectl exec -n stackrox deployment/results-controller-controller-manager -- \
  curl -k https://central.stackrox.svc:443/v1/ping
```

#### Missing Results
```bash
# Check if namespace has workloads
kubectl get deployments -n problem-namespace

# Verify controller is watching the namespace
kubectl get stackroxresults -n problem-namespace

# Check for system namespace exclusions in controller logs
```

### Debug Mode

Enable debug logging:
```bash
kubectl patch deployment results-controller-controller-manager -n stackrox \
  --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--zap-log-level=debug"}]'
```

## Development

See [TESTING.md](TESTING.md) for comprehensive testing strategies and procedures.

### Building

```bash
# Run tests
make test

# Build binary
make build

# Build and push image
make docker-build docker-push IMG=myregistry/results-controller:latest

# Deploy to cluster
make deploy IMG=myregistry/results-controller:latest
```

### Code Generation

```bash
# Generate CRD manifests
make manifests

# Generate DeepCopy methods
make generate
```

## Security Considerations

- **Authentication**: Uses Kubernetes service account tokens for Central API access
- **Authorization**: Respects Kubernetes RBAC for CR access
- **Data Sensitivity**: Results contain security information - ensure appropriate RBAC
- **Network Security**: Controller communicates with Central over TLS
- **Least Privilege**: Controller runs with minimal required permissions

## Contributing

1. Follow the existing code patterns from `config-controller`
2. Ensure comprehensive unit test coverage
3. Update documentation for any configuration changes
4. Test in a live environment before submitting PRs

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../LICENSE) file for details.