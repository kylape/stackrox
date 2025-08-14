# Testing Strategy for Results Controller

This document outlines the comprehensive testing strategy for the StackRox Results Controller, which exposes security results through Kubernetes Custom Resources.

## Overview

The testing strategy covers multiple layers:
- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions in a live environment
- **Manual Testing**: End-to-end validation procedures
- **Performance Testing**: Validate scalability and resource usage

## Unit Testing

### Test Structure

Unit tests are organized into three main categories:

1. **API Types Tests** (`api/v1alpha1/*_test.go`)
2. **Central Client Tests** (`pkg/client/*_test.go`)  
3. **Controller Tests** (`internal/controller/*_test.go`)

### Test Patterns and Conventions

#### Naming Convention
- Test files: `*_test.go`
- Test functions: `TestFunctionName_Scenario`
- Table-driven tests: Use descriptive test names in struct fields

#### Mock Usage Guidelines

**Central Client Mocks**
```go
// Generate mocks using mockgen
//go:generate mockgen-wrapper CentralClient

// Use mocks in tests
mockClient := mocks.NewMockCentralClient(ctrl)
mockClient.EXPECT().
    GetVulnerabilitiesForNamespace(ctx, namespace).
    Return(expectedData, nil).
    Times(1)
```

**Kubernetes Client Mocks**
```go
// Use controller-runtime's fake client for K8s API interactions
fakeClient := fake.NewClientBuilder().
    WithScheme(scheme).
    WithRuntimeObjects(existingObjects...).
    Build()
```

#### Test Data Generation

**Vulnerability Test Data**
```go
func createTestVulnerability(cve string, severity string) platformv1alpha1.VulnerabilityInfo {
    return platformv1alpha1.VulnerabilityInfo{
        CVE:      cve,
        Severity: severity,
        CVSS:     7.5,
        Fixable:  true,
        AffectedImages: []string{"nginx:1.0"},
    }
}
```

**Policy Violation Test Data**
```go
func createTestPolicyViolation(alertID string, policyName string) platformv1alpha1.PolicyViolationInfo {
    return platformv1alpha1.PolicyViolationInfo{
        AlertID:    alertID,
        PolicyName: policyName,
        Severity:   "High",
        State:      "Active",
    }
}
```

### Running Unit Tests

```bash
# Run all unit tests
make test

# Run tests with coverage
make test-coverage

# Run specific package tests
go test ./pkg/client/...
go test ./internal/controller/...
go test ./api/v1alpha1/...

# Run with verbose output
go test -v ./...

# Run specific test
go test -run TestStackRoxResultsReconciler_Reconcile ./internal/controller/
```

### Test Coverage Requirements

- **Minimum Coverage**: 80% for all packages
- **Critical Paths**: 95% coverage for controller reconcile logic and Central client authentication
- **Error Handling**: All error scenarios must be tested

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Integration Testing in Live Environments

Since we don't use envtest, integration testing occurs in live Kubernetes environments.

### Test Environment Setup

#### Prerequisites
- Kubernetes cluster (minikube, kind, or cluster)
- StackRox Central deployed and accessible
- Results controller deployed
- Test namespace with sample workloads

#### Environment Configuration
```bash
# Set up test environment
export KUBECONFIG=/path/to/test/kubeconfig
export STACKROX_CENTRAL_ENDPOINT=https://central.stackrox.svc:443
export TEST_NAMESPACE=integration-test
```

### Integration Test Scenarios

#### 1. End-to-End Flow Validation
```bash
# Create test namespace with vulnerable deployment
kubectl create namespace ${TEST_NAMESPACE}
kubectl apply -f test/fixtures/vulnerable-deployment.yaml -n ${TEST_NAMESPACE}

# Verify StackRoxResults CR is created
kubectl get stackroxresults -n ${TEST_NAMESPACE}

# Verify data is populated
kubectl get stackroxresults stackrox-results -n ${TEST_NAMESPACE} -o yaml
```

#### 2. Controller Restart Resilience
```bash
# Restart controller pod
kubectl delete pod -l app=results-controller -n stackrox

# Verify sync continues after restart
kubectl logs -l app=results-controller -n stackrox --follow
```

#### 3. Central Connection Recovery
```bash
# Temporarily block Central access
kubectl patch networkpolicy deny-central --type='merge' -p='{"spec":{"egress":[]}}'

# Verify controller handles errors gracefully
kubectl get stackroxresults -A -o custom-columns="NAMESPACE:.metadata.namespace,STATUS:.status.syncStatus,MESSAGE:.status.syncMessage"

# Restore Central access
kubectl delete networkpolicy deny-central
```

### Manual Testing Procedures

#### 1. RBAC Validation

**Test Namespace Admin Access**
```bash
# Create test user with namespace admin role
kubectl create serviceaccount test-user -n ${TEST_NAMESPACE}
kubectl create rolebinding test-user-admin --clusterrole=admin --serviceaccount=${TEST_NAMESPACE}:test-user -n ${TEST_NAMESPACE}

# Test access to StackRoxResults
kubectl auth can-i get stackroxresults --as=system:serviceaccount:${TEST_NAMESPACE}:test-user -n ${TEST_NAMESPACE}
kubectl auth can-i update stackroxresults --as=system:serviceaccount:${TEST_NAMESPACE}:test-user -n ${TEST_NAMESPACE}
```

**Test Cross-Namespace Access Denial**
```bash
# Verify user cannot access other namespace results
kubectl auth can-i get stackroxresults --as=system:serviceaccount:${TEST_NAMESPACE}:test-user -n other-namespace
```

#### 2. Data Accuracy Validation

**Compare with Central UI**
1. View vulnerabilities in Central UI for test namespace
2. Compare with StackRoxResults CR data
3. Verify counts and severity distributions match

**Verify Real-Time Updates**
1. Deploy new vulnerable image to test namespace
2. Wait for sync interval (default 5 minutes)
3. Verify new vulnerabilities appear in StackRoxResults

#### 3. Performance Validation

**Large Namespace Testing**
```bash
# Deploy many workloads to test namespace
for i in {1..50}; do
  kubectl create deployment test-app-$i --image=nginx:1.0 -n ${TEST_NAMESPACE}
done

# Monitor controller resource usage
kubectl top pod -l app=results-controller -n stackrox

# Verify sync completes successfully
kubectl get stackroxresults stackrox-results -n ${TEST_NAMESPACE} -o jsonpath='{.status.syncStatus}'
```

### Performance Testing

#### Resource Usage Monitoring

**Controller Metrics**
```bash
# Check memory usage
kubectl top pod -l app=results-controller -n stackrox

# Check CPU usage over time
kubectl logs -l app=results-controller -n stackrox | grep "memory\|cpu"
```

**API Call Efficiency**
```bash
# Monitor Central API call frequency
kubectl logs -l app=results-controller -n stackrox | grep "Central API"

# Verify respects rate limits
kubectl describe pod -l app=results-controller -n stackrox
```

#### Scale Testing

**Namespace Scale**
- Test with 1, 10, 50, 100 namespaces
- Monitor sync time and resource usage
- Verify no memory leaks

**Result Volume Scale**
- Test namespaces with 0, 10, 100, 500+ vulnerabilities
- Verify pagination and limits work correctly
- Check etcd storage impact

#### Performance Benchmarks

| Metric | Target | Measurement Method |
|--------|--------|--------------------|
| Sync Time | < 30s per namespace | Controller logs |
| Memory Usage | < 256Mi peak | `kubectl top pod` |
| CPU Usage | < 100m average | `kubectl top pod` |
| API Calls | < 10 per sync | Central access logs |

### Troubleshooting Common Test Failures

#### Authentication Failures
```bash
# Check service account token
kubectl get secret -n stackrox | grep results-controller
kubectl describe secret results-controller-token-xxx -n stackrox

# Verify Central M2M configuration
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://central.stackrox.svc/v1/auth/m2m/exchange
```

#### Sync Failures
```bash
# Check controller logs
kubectl logs -l app=results-controller -n stackrox --tail=100

# Verify Central connectivity
kubectl exec -it deployment/results-controller -n stackrox -- \
  curl -k https://central.stackrox.svc:443/v1/ping

# Check CRD status
kubectl get stackroxresults -A -o custom-columns="NAMESPACE:.metadata.namespace,STATUS:.status.syncStatus,LAST_SYNC:.status.lastSyncTime"
```

#### RBAC Issues
```bash
# Check controller permissions
kubectl auth can-i create stackroxresults --as=system:serviceaccount:stackrox:results-controller

# Verify CRD installation
kubectl get crd stackroxresults.platform.stackrox.io

# Check namespace access
kubectl get namespaces --as=system:serviceaccount:stackrox:results-controller
```

#### Performance Issues
```bash
# Check resource limits
kubectl describe pod -l app=results-controller -n stackrox

# Monitor Central API latency
kubectl logs -l app=results-controller -n stackrox | grep "latency\|duration"

# Check for goroutine leaks
kubectl exec -it deployment/results-controller -n stackrox -- \
  curl http://localhost:8080/debug/pprof/goroutine?debug=1
```

### Continuous Integration

#### Pre-commit Hooks
```bash
# Run tests before commit
make test
make lint
make vet
```

#### CI Pipeline Tests
```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]
jobs:
  unit-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: 1.23
      - run: make test-coverage
      - run: make lint
```

### Test Data Management

#### Test Fixtures
- Store test YAML files in `test/fixtures/`
- Use realistic but anonymized data
- Include edge cases (empty results, large datasets)

#### Mock Data Consistency
- Keep mock data synchronized with real API responses
- Update mocks when Central API changes
- Validate mock data structure matches protobuf definitions

### Security Testing

#### RBAC Validation
- Test with various Kubernetes roles
- Verify namespace isolation
- Check service account permissions

#### Data Sensitivity
- Ensure no secrets in logs
- Verify data at rest encryption
- Test access control boundaries

This testing strategy ensures comprehensive coverage of the Results Controller functionality while maintaining security and performance standards.