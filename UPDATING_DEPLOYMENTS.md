# Updating Existing StackRox Deployments

This guide explains how the deploy scripts handle existing deployments and how to maintain uptime during updates.

## Deploy Script Behavior with Existing Deployments

### Detection and Prompting

When you run deployment scripts on an existing installation:

1. **Non-CI Environments** (`common/k8sbased.sh:150-152`):
   * Script detects existing Central deployment
   * Prompts: "A central deployment already exists. Do you want to continue with a new deployment? [y/n]"
   * Exits if you decline
   * Proceeds if you confirm

2. **CI Environments**:
   * Skips the prompt
   * Automatically proceeds with update/redeployment

### What Happens During Redeployment

#### Using Helm (Default and Recommended)

```bash
# Helm is the default for custom deployment scripts
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

**Behavior**:
* Runs `helm upgrade --install stackrox-central-services`
* Performs in-place upgrade of existing release
* Kubernetes performs rolling updates for deployments
* **Default**: Replaces all values with new configuration
* **With `HELM_REUSE_VALUES=true`**: Preserves existing configuration

**Uptime Impact**:
* ✅ Rolling updates for deployments (minimal downtime)
* ⚠️ May regenerate secrets/certificates (can cause brief interruption)
* ⚠️ ConfigMap/Secret changes trigger pod restarts

#### Using kubectl

```bash
# Override to use kubectl instead of Helm
OUTPUT_FORMAT=kubectl ./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

**Behavior**:
* Runs `kubectl apply -R -f` on generated manifests
* Updates existing resources in-place
* Creates new resources if they don't exist

**Uptime Impact**:
* ✅ Deployments get rolling updates
* ⚠️ Secrets/ConfigMaps get regenerated
* ⚠️ Services may be recreated (brief connection drops)
* ⚠️ TLS certificates regenerated (can break existing connections)

## Uptime Considerations

### Resources That Cause Disruption

1. **TLS Certificates**
   * Deploy scripts regenerate on each run
   * Central API clients may experience brief connection errors
   * UI sessions may be interrupted

2. **Admin Password**
   * Regenerated unless preserved
   * Active sessions terminated

3. **ConfigMaps/Secrets**
   * Changes trigger automatic pod restarts
   * Brief service interruption during restart

4. **Service Resources**
   * Recreation can cause DNS/connectivity blips
   * Load balancer IP may change

### Resources That Support Rolling Updates

1. **Deployment Images**
   * Changing image tags triggers rolling updates
   * Kubernetes updates one pod at a time
   * Old pods remain until new pods are ready

2. **Resource Limits**
   * Changes applied via rolling update
   * No downtime for properly configured deployments

3. **Environment Variables**
   * Trigger rolling pod replacement
   * Maintained availability if replicas > 1

## Recommended Update Strategies

### Strategy 1: Zero-Downtime Image Update (Best for Iterative Development)

**Use Case**: You're iterating on code changes and need to test frequently

```bash
# Initial deployment
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Later: update just the image (zero downtime)
./update-main-image.sh xyz789
```

**Advantages**:
* ✅ No certificate regeneration
* ✅ No secret recreation
* ✅ True rolling update
* ✅ Instant rollback capability
* ✅ Works with any deployment method

**Limitations**:
* Only updates container images
* Doesn't change other configuration

**How it works**:
```bash
# Updates deployment image references directly
kubectl set image deployment/central central=localhost:5000/stackrox/main:xyz789
kubectl rollout status deployment/central  # Waits for completion
```

### Strategy 2: Helm with Reuse Values (Best for Production Updates)

**Use Case**: You want to update multiple things while preserving most configuration

```bash
# Initial deployment (Helm is default)
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Update with new image, preserve everything else
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh xyz789 4.6.x-nightly-20241003
```

**Advantages**:
* ✅ Preserves certificates
* ✅ Preserves secrets
* ✅ Preserves custom configuration
* ✅ Can update multiple components at once
* ✅ Helm tracks release history

**Limitations**:
* Requires initial Helm deployment
* May not pick up new default values

**Behavior** (`common/k8sbased.sh:449-461`):
```bash
if [[ "${HELM_REUSE_VALUES}" == "true" ]]; then
    helm upgrade --install stackrox-central-services --reuse-values ...
else
    helm upgrade --install stackrox-central-services -f values.yaml ...
fi
```

### Strategy 3: Full Redeployment (Use for Major Changes)

**Use Case**: You need to change fundamental configuration (storage, TLS, namespaces)

```bash
# Redeploy with all new configuration
./deploy-custom-main.sh xyz789 4.6.x-nightly-20241003
```

**Advantages**:
* ✅ Applies all configuration changes
* ✅ Regenerates certificates
* ✅ Ensures consistency

**Limitations**:
* ⚠️ Brief service interruption
* ⚠️ Active sessions terminated
* ⚠️ Certificates change

**When to use**:
* Changing storage configuration
* Updating TLS certificates
* Changing namespaces
* Major version upgrades

## Detailed: update-main-image.sh Script

The `update-main-image.sh` script provides zero-downtime updates:

### What It Does

```bash
./update-main-image.sh xyz789 stackrox
```

1. **Validates** deployment exists
2. **Shows** current image versions
3. **Prompts** for confirmation
4. **Updates** images using `kubectl set image`:
   * Central deployment
   * Sensor deployment (if exists)
   * Admission Controller deployment (if exists)
   * Collector daemonset (if exists)
5. **Waits** for each rollout to complete
6. **Reports** success or failure

### Rolling Update Process

For each component:

```bash
# Update image reference
kubectl set image deployment/central central=localhost:5000/stackrox/main:xyz789

# Kubernetes automatically:
# 1. Creates new ReplicaSet with new image
# 2. Scales up new pods (one at a time by default)
# 3. Waits for new pod to be ready
# 4. Scales down old pod
# 5. Repeats until all pods updated
```

### Rollback Capability

If something goes wrong:

```bash
# Automatic rollback to previous version
kubectl rollout undo deployment/central -n stackrox

# Or rollback to specific revision
kubectl rollout history deployment/central -n stackrox
kubectl rollout undo deployment/central --to-revision=2 -n stackrox
```

### Health Checks

Kubernetes ensures zero downtime by:
* Waiting for new pods to pass readiness probes
* Keeping old pods running until new pods are ready
* Respecting pod disruption budgets (if configured)

## Comparison Matrix

| Strategy | Image Update | Config Update | Cert Regen | Downtime | Rollback | Best For |
|----------|--------------|---------------|------------|----------|----------|----------|
| `update-main-image.sh` | ✅ | ❌ | ❌ | None | Instant | Iterative dev |
| Helm + reuse-values (default) | ✅ | ✅ | ❌ | Minimal | Helm history | Prod updates |
| Full redeploy (Helm, default) | ✅ | ✅ | ✅ | Brief | Helm history | Major changes |
| Full redeploy (kubectl) | ✅ | ✅ | ✅ | Brief | Manual | Legacy/simple |

## Best Practices

### 1. For Development Iterations

```bash
# Initial setup (once)
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Each code change
docker build -t localhost:5000/stackrox/main:abc124 .
docker push localhost:5000/stackrox/main:abc124
./update-main-image.sh abc124

# Fast feedback loop, no downtime
```

### 2. For Testing Different Nightly Builds

```bash
# Test with different scanner versions
export SCANNER_IMAGE="quay.io/rhacs-eng/scanner:4.6.x-nightly-20241001"
OUTPUT_FORMAT=helm HELM_REUSE_VALUES=true \
  ./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

### 3. For Production-like Environments

```bash
# Helm is used by default for better lifecycle management
STORAGE=pvc \
  STORAGE_SIZE=50 \
  MONITORING_SUPPORT=true \
  ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Updates preserve configuration
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh xyz789 4.6.x-nightly-20241003
```

### 4. For CI/CD Pipelines

```bash
# Set CI=true to skip prompts (Helm is default)
export CI=true
./deploy-custom-main.sh ${GIT_SHA} ${NIGHTLY_TAG}
```

## Troubleshooting Updates

### Update Stuck in Rollout

```bash
# Check rollout status
kubectl rollout status deployment/central -n stackrox

# Check pod events
kubectl describe pod -l app=central -n stackrox

# Check for image pull errors
kubectl get events -n stackrox --sort-by='.lastTimestamp'
```

### Rollback Required

```bash
# Quick rollback
kubectl rollout undo deployment/central -n stackrox

# Verify rollback
kubectl rollout status deployment/central -n stackrox
kubectl get pods -n stackrox
```

### Connection Issues After Update

```bash
# Check if certificates changed
kubectl get secret -n stackrox central-tls -o yaml

# Restart port-forward if using local access
pkill -f "port-forward.*central"
kubectl port-forward -n stackrox svc/central 8000:443
```

### Update Fails with "field is immutable" Error

Some fields (like Service clusterIP) can't be updated. Solutions:

```bash
# Option 1: Delete and recreate (brief downtime)
kubectl delete svc central -n stackrox
./deploy/k8s/central.sh

# Option 2: Delete entire namespace and redeploy
kubectl delete namespace stackrox
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

## Advanced: Custom Update Scripts

For more control, you can create custom update workflows:

```bash
#!/usr/bin/env bash
# custom-update.sh

NEW_TAG="$1"
NAMESPACE="${2:-stackrox}"

# Pre-update checks
kubectl get deployment -n "$NAMESPACE" || exit 1

# Update with validation
kubectl set image deployment/central \
  central="localhost:5000/stackrox/main:${NEW_TAG}" \
  -n "$NAMESPACE"

# Wait with timeout
if ! kubectl rollout status deployment/central -n "$NAMESPACE" --timeout=5m; then
  echo "Update failed, rolling back..."
  kubectl rollout undo deployment/central -n "$NAMESPACE"
  exit 1
fi

# Smoke test
if ! kubectl exec -n "$NAMESPACE" deployment/central -- curl -k https://localhost:8443/v1/ping; then
  echo "Health check failed, rolling back..."
  kubectl rollout undo deployment/central -n "$NAMESPACE"
  exit 1
fi

echo "Update successful!"
```

## Summary

**For maintaining uptime during updates:**

1. **Use `update-main-image.sh`** for simple image updates (zero downtime)
2. **Use Helm with `HELM_REUSE_VALUES=true`** for config changes (minimal downtime)
3. **Avoid full redeployment** unless necessary (causes service interruption)
4. **Always test rollback** procedures in non-production environments
5. **Monitor rollout status** to catch issues early
6. **Use health checks** to ensure pods are ready before traffic switches
