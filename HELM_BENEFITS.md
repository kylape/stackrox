# Why Helm is Default for Custom Deployments

The custom deployment scripts now use Helm by default instead of kubectl manifests. This provides several advantages for managing StackRox deployments.

## Changes Made

All custom deployment scripts now set:
```bash
export OUTPUT_FORMAT=helm  # For Central deployments
export SENSOR_HELM_DEPLOY=true  # For Sensor deployments
```

### Affected Scripts
* `deploy-custom-main.sh` - Sets `OUTPUT_FORMAT=helm`
* `deploy-custom-central.sh` - Sets `OUTPUT_FORMAT=helm`
* `deploy-custom-sensor.sh` - Sets `SENSOR_HELM_DEPLOY=true`

## Why Helm is Better

### 1. Better Upgrade Management

**Helm**:
```bash
# Initial deployment
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

# Update to new version - preserves config
export HELM_REUSE_VALUES=true
./deploy-custom-central.sh xyz789 4.6.x-nightly-20241003
```

**kubectl manifests**:
```bash
# Every redeployment regenerates everything
# No built-in way to preserve existing config
./deploy-custom-central.sh xyz789 4.6.x-nightly-20241003
```

### 2. Release History and Rollback

**Helm**:
```bash
# View deployment history
helm history stackrox-central-services -n stackrox

# Rollback to previous version
helm rollback stackrox-central-services -n stackrox

# Rollback to specific revision
helm rollback stackrox-central-services 2 -n stackrox
```

**kubectl**:
```bash
# Limited rollback capability
kubectl rollout undo deployment/central -n stackrox

# No history for ConfigMaps, Secrets, Services
# Manual restoration required
```

### 3. Configuration Preservation

**Helm** with `HELM_REUSE_VALUES=true`:
* ✅ Preserves certificates across updates
* ✅ Preserves secrets (admin password, etc.)
* ✅ Preserves custom configuration
* ✅ Only updates what you specify

**kubectl apply**:
* ⚠️ Regenerates certificates on each run
* ⚠️ Regenerates secrets
* ⚠️ Replaces all configuration
* ⚠️ Active sessions may be interrupted

### 4. Atomic Updates

**Helm**:
```bash
# All resources updated together atomically
# Rollback available if anything fails
helm upgrade --install --atomic stackrox-central-services ...
```

**kubectl**:
```bash
# Resources applied individually
# Partial failures leave inconsistent state
# No automatic rollback
kubectl apply -R -f central-deploy/
```

### 5. Value Composition

**Helm**:
```bash
# Layer multiple value files
helm upgrade --install stackrox-central-services \
  -f values-public.yaml \
  -f local-dev-values.yaml \
  -f my-custom-values.yaml
```

**kubectl**:
```bash
# Must manually patch after deployment
kubectl apply -R -f central-deploy/
kubectl patch deployment central --patch-file my-patch.yaml
```

### 6. Release Status Tracking

**Helm**:
```bash
# See current release status
helm list -n stackrox

# Get detailed status
helm status stackrox-central-services -n stackrox

# See what values are currently deployed
helm get values stackrox-central-services -n stackrox
```

**kubectl**:
```bash
# No built-in release tracking
# Must manually check each resource
kubectl get all -n stackrox
```

## Deployment Workflow Comparison

### Helm Workflow (Default)

```bash
# Day 1: Initial deployment
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Day 2: Update main image only (preserve everything else)
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh xyz789 4.6.x-nightly-20241003

# Day 3: Update scanner version (preserve everything else)
export HELM_REUSE_VALUES=true
export SCANNER_IMAGE_TAG=4.6.x-nightly-20241005
./deploy-custom-central.sh xyz789 4.6.x-nightly-20241005

# Something broke? Rollback
helm rollback stackrox-central-services -n stackrox

# Check what changed
helm diff revision stackrox-central-services 1 2 -n stackrox
```

### kubectl Workflow (Legacy)

```bash
# Day 1: Initial deployment
OUTPUT_FORMAT=kubectl ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Day 2: Update - regenerates everything!
OUTPUT_FORMAT=kubectl ./deploy-custom-main.sh xyz789 4.6.x-nightly-20241003
# Certificates regenerated → API clients break
# Secrets regenerated → sessions terminated
# ConfigMaps regenerated → pods restart

# Rollback requires manual steps
kubectl set image deployment/central central=localhost:5000/stackrox/main:abc123
# But certificates/secrets/configmaps still changed!
```

## Real-World Scenarios

### Scenario 1: Testing Multiple Image Versions

**With Helm** (seamless):
```bash
# Deploy version 1
./deploy-custom-main.sh v1 4.6.x-nightly-20241003

# Test version 2 (keeps certs, secrets, etc.)
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh v2 4.6.x-nightly-20241003

# Rollback if v2 has issues
helm rollback stackrox-central-services

# Or try version 3
./deploy-custom-main.sh v3 4.6.x-nightly-20241003
```

**Without Helm** (painful):
```bash
# Deploy version 1
OUTPUT_FORMAT=kubectl ./deploy-custom-main.sh v1 4.6.x-nightly-20241003

# Update to version 2
# Problem: Certificates regenerated, must update all API clients!
OUTPUT_FORMAT=kubectl ./deploy-custom-main.sh v2 4.6.x-nightly-20241003

# Rollback requires:
kubectl set image deployment/central central=localhost:5000/stackrox/main:v1
# But certs/secrets still changed - need manual restore
```

### Scenario 2: Updating Nightly Build Components

**With Helm**:
```bash
# Update scanner to newer nightly, keep custom main image
export HELM_REUSE_VALUES=true
export SCANNER_IMAGE_TAG=4.6.x-nightly-20241010
./deploy-custom-central.sh abc123 4.6.x-nightly-20241010
```

**Without Helm**:
```bash
# Must redeploy everything
export SCANNER_IMAGE_TAG=4.6.x-nightly-20241010
OUTPUT_FORMAT=kubectl ./deploy-custom-central.sh abc123 4.6.x-nightly-20241010
# Everything regenerated unnecessarily
```

### Scenario 3: Production Deployment Updates

**With Helm**:
```bash
# Initial production deployment
STORAGE=pvc STORAGE_SIZE=100 MONITORING_SUPPORT=true \
  ./deploy-custom-main.sh v1.0 4.6.0

# Update to v1.1 - zero service interruption
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh v1.1 4.6.0

# Check deployment status
helm status stackrox-central-services -n stackrox

# Instant rollback if needed
helm rollback stackrox-central-services
```

**Without Helm**:
```bash
# Production deployment
OUTPUT_FORMAT=kubectl \
  STORAGE=pvc STORAGE_SIZE=100 MONITORING_SUPPORT=true \
  ./deploy-custom-main.sh v1.0 4.6.0

# Update to v1.1
OUTPUT_FORMAT=kubectl ./deploy-custom-main.sh v1.1 4.6.0
# ⚠️ Certificates regenerated - client connections break!
# ⚠️ Secrets regenerated - need to redistribute admin password
# ⚠️ No easy rollback path
```

## Helm-Specific Features Used

### 1. Release Management

The deploy scripts leverage Helm's release tracking:
```bash
# From common/k8sbased.sh:470
helm upgrade --install stackrox-central-services \
  --namespace stackrox \
  --create-namespace \
  "${helm_args[@]}"
```

### 2. Value Layering

Multiple value files for different environments:
```bash
# From common/k8sbased.sh:360-364
if [[ "$(local_dev)" == "true" ]]; then
  helm_args+=(-f "$common_dir/local-dev-values.yaml")
elif [[ "${CI}" == "true" ]]; then
  helm_args+=(-f "$common_dir/ci-values.yaml")
fi
```

### 3. Chart Validation

Helm linting in CI:
```bash
# From common/k8sbased.sh:443-447
if [[ "${CI}" == "true" ]]; then
  helm lint "$unzip_dir/chart" \
    "${helm_args[@]}"
fi
```

### 4. Reuse Values

Preserve configuration across updates:
```bash
# From common/k8sbased.sh:449-461
if [[ "${HELM_REUSE_VALUES}" == "true" ]]; then
  helm_args+=(--reuse-values)
else
  helm_args+=(-f values-public.yaml -f values-private.yaml)
fi
```

## How to Override (Use kubectl Instead)

If you need kubectl for specific reasons:

```bash
# Override for single deployment
OUTPUT_FORMAT=kubectl ./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

# Set in environment
export OUTPUT_FORMAT=kubectl
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

## Migration Path

### If You Have Existing kubectl Deployments

**Option 1: Migrate to Helm (Recommended)**

```bash
# Delete existing deployment
kubectl delete namespace stackrox

# Redeploy with Helm
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

**Option 2: Import Existing Resources**

```bash
# Helm can adopt existing resources
helm upgrade --install stackrox-central-services \
  --namespace stackrox \
  --set-string annotations."meta\.helm\.sh/release-name"=stackrox-central-services \
  --set-string annotations."meta\.helm\.sh/release-namespace"=stackrox \
  <chart-path>
```

**Option 3: Continue with kubectl**

```bash
# Keep using kubectl
export OUTPUT_FORMAT=kubectl
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

## Summary: Why Helm is Default

| Capability | Helm | kubectl |
|------------|------|---------|
| Preserve certificates on update | ✅ (with reuse-values) | ❌ Regenerates |
| Preserve secrets on update | ✅ (with reuse-values) | ❌ Regenerates |
| Release history | ✅ Full history | ❌ Limited |
| Easy rollback | ✅ One command | ⚠️ Manual |
| Atomic updates | ✅ Built-in | ❌ Not available |
| Configuration composition | ✅ Value files | ⚠️ Patches only |
| Status tracking | ✅ Built-in | ❌ Manual |
| Template validation | ✅ Linting | ❌ Not available |
| Production-ready | ✅ Industry standard | ⚠️ Basic |

**Bottom line**: Helm provides better lifecycle management, easier updates, and production-grade features with minimal downtime - making it the best choice for custom deployments.
