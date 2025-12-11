# Running E2E Tests In-Cluster

This guide explains how to run StackRox E2E tests as pods inside a Kubernetes cluster, allowing direct access to StackRox services without port-forwarding.

## Overview

E2E tests are compiled into a static binary and packaged in a container image based on the StackRox main image. The tests run as pods in the `stackrox` namespace with direct access to Central and other services.

## Prerequisites

* StackRox deployed in the cluster
* Admin password available (typically stored in session directory)
* `podman` or `docker` for building images
* Access to the kind registry at `localhost:5001`

## Quick Start

### 1. Build the Test Binary

```bash
cd /root/workspace/sessions/local-e2e/stackrox/tests

# Build static test binary
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -tags test_e2e -o e2e-test.bin
```

### 2. Build the Container Image

```bash
# Build and push to kind registry
podman build -f Dockerfile.e2e -t localhost:5001/e2e-test:latest .
podman push localhost:5001/e2e-test:latest --tls-verify=false
```

### 3. Run the Tests

```bash
# Deploy test pod
kubectl apply -f e2e-test-pod.yaml

# Watch logs
kubectl logs -n stackrox e2e-test -f

# Check results
kubectl get pod -n stackrox e2e-test
kubectl logs -n stackrox e2e-test
```

## Running Specific Tests

Edit `e2e-test-pod.yaml` and modify the `args` section:

```yaml
args: ["-test.v", "-test.run", "TestPing"]  # Run specific test
args: ["-test.v", "-test.run", "TestPing|TestBackup"]  # Run multiple tests
args: ["-test.v"]  # Run all tests
```

Then reapply:

```bash
kubectl delete pod -n stackrox e2e-test --ignore-not-found
kubectl apply -f e2e-test-pod.yaml
kubectl logs -n stackrox e2e-test -f
```

## Files

* `Dockerfile.e2e` - Dockerfile for building the test image
* `.dockerignore` - Excludes unnecessary files from build context
* `e2e-test-pod.yaml` - Kubernetes pod specification
* `e2e-test.bin` - Compiled test binary (generated)

## Configuration

The test pod uses these environment variables:

* `ROX_ADMIN_PASSWORD` - Admin password for authentication
* `API_ENDPOINT` - Central service endpoint (default: `central.stackrox.svc:443`)
* `ROX_USERNAME` - Admin username (default: `admin`)

Update the password in `e2e-test-pod.yaml` to match your deployment:

```bash
# Get current admin password
cat /root/workspace/sessions/local-e2e/admin-password.txt
```

## Troubleshooting

### Binary not found errors

Make sure the binary is statically compiled:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -tags test_e2e -o e2e-test.bin
```

### Image pull errors

Verify the image is in the registry:

```bash
podman images localhost:5001/e2e-test
```

Rebuild and push:

```bash
podman build --no-cache -f Dockerfile.e2e -t localhost:5001/e2e-test:latest .
podman push localhost:5001/e2e-test:latest --tls-verify=false
```

### Connection failures

Verify Central is running:

```bash
kubectl get pods -n stackrox
kubectl get svc -n stackrox central
```

Check the pod logs for specific errors:

```bash
kubectl logs -n stackrox e2e-test
kubectl describe pod -n stackrox e2e-test
```

## Available Tests

List all available tests:

```bash
podman run --rm --entrypoint /bin/sh localhost:5001/e2e-test:latest -c "/test/e2e-test.bin -test.list ."
```

## Example Output

Successful test run:

```
=== RUN   TestPing
    connect_to_central.go:120: gRPC call /v1.PingService/Ping succeeded in 86.709294ms
--- PASS: TestPing (0.09s)
PASS
```

## Cleanup

```bash
kubectl delete pod -n stackrox e2e-test
```

## Notes

* Tests run with `restartPolicy: Never` so the pod completes after running
* The StackRox main image provides the necessary libraries and runtime environment
* Static compilation (CGO_ENABLED=0) is required for portability
* `.dockerignore` prevents symlink issues during image builds
