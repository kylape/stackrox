# Deployment Methods Comparison

## Quick Decision Guide

```
Do you have the StackRox source code?
├─ Yes → Use deploy-from-source.sh (FASTEST)
│   └─ Initial deploy: ~1 minute (roxctl helm output + Helm)
│   └─ Updates: ~10 seconds (Helm reuse chart)
│
└─ No → Use deploy-custom-main.sh
    └─ Initial deploy: ~3-5 minutes (roxctl central generate + Helm)
    └─ Updates: Use update-main-image.sh (~30 seconds)
```

## All Methods Compared

### 1. deploy-from-source.sh (Requires Source Code)

**What it does**:
```bash
# Uses source code Helm chart templates at image/templates/helm/
roxctl helm output central-services \
  --output-dir ./helm-output
  # Renders .htpl meta-templates → actual Helm chart

helm upgrade --install stackrox-central-services \
  ./helm-output/stackrox-central-services-chart/ \
  --set image.tag=abc123
```

**Performance**:
* Initial deployment: ~1 minute
  * roxctl helm output: ~5-10 seconds (local) or ~15 seconds (Docker)
  * Helm deploy: ~2-3 minutes
  * Health checks: ~30 seconds
* Subsequent updates: ~10 seconds (Helm only, reuse chart)

**Pros**:
* ✅ **Fastest initial deployment**
* ✅ Chart rendered once, reusable
* ✅ Full Helm values control
* ✅ Can modify chart templates
* ✅ Lightweight roxctl operation
* ✅ Best for active StackRox development

**Cons**:
* ❌ Requires source code checkout
* ❌ Requires roxctl (local or Docker)
* ❌ Chart needs re-rendering if you switch branches

**Best for**:
* StackRox developers
* Testing chart changes
* Rapid iteration on StackRox itself
* Maximum control over deployment

**Usage**:
```bash
# Initial
./deploy-from-source.sh abc123 4.6.x-nightly-20241003

# Updates (chart already rendered)
helm upgrade stackrox-central-services \
  ./helm-output/stackrox-central-services-chart/ \
  --reuse-values --set image.tag=abc124
```

---

### 2. deploy-custom-main.sh (No Source Required)

**What it does**:
```bash
# Generates complete Helm chart via roxctl
roxctl central generate kubernetes \
  --output-format helm \
  -i localhost:5001/stackrox/main:abc123 \
  --central-db-image quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003
  # Generates chart with all settings baked in

helm upgrade --install stackrox-central-services \
  ./deploy/k8s/central-deploy/chart/
```

**Performance**:
* Initial deployment: ~3-5 minutes
  * roxctl central generate: ~30 seconds (Docker pull + generate)
  * Helm deploy: ~2-3 minutes
  * Health checks: ~30 seconds
* Subsequent updates: ~2-4 minutes (regenerates chart each time)

**Pros**:
* ✅ Works without source code
* ✅ Simple script interface
* ✅ All configuration via environment variables
* ✅ Platform detection (K8s/OpenShift)
* ✅ Uses Helm by default

**Cons**:
* ⚠️ Slower than source-based approach
* ⚠️ Regenerates chart on each deployment
* ⚠️ Less flexible (limited to roxctl flags)

**Best for**:
* Deploying pre-built images
* Users without source code access
* Simple deployment scenarios
* CI/CD pipelines

**Usage**:
```bash
# Initial
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Updates (for faster updates, use update-main-image.sh instead)
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh abc124 4.6.x-nightly-20241003
```

---

### 3. update-main-image.sh (Fastest Updates)

**What it does**:
```bash
# Direct kubectl image update
kubectl set image deployment/central \
  central=localhost:5001/stackrox/main:abc124

kubectl rollout status deployment/central
```

**Performance**:
* ~30-60 seconds total
  * kubectl update: ~10 seconds
  * Rolling update: ~30 seconds
  * Health check: ~10 seconds

**Pros**:
* ✅ **Fastest update method**
* ✅ No roxctl needed
* ✅ No Helm needed
* ✅ True rolling update (zero downtime)
* ✅ Instant rollback capability
* ✅ Works with any deployment method

**Cons**:
* ⚠️ Only updates container images
* ⚠️ Can't change other configuration

**Best for**:
* Daily development iterations
* Testing code changes quickly
* Production hotfixes
* Any scenario where only image changes

**Usage**:
```bash
# After any initial deployment method
./update-main-image.sh abc124
./update-main-image.sh abc125
# ... iterate rapidly ...
```

---

## Performance Comparison Table

| Method | Initial Deploy | Image Update | Config Update | roxctl Needed | Chart Reusable |
|--------|---------------|--------------|---------------|---------------|----------------|
| **deploy-from-source.sh** | ~1 min | ~10s (Helm) | ~10s (Helm) | Once (helm output) | ✅ Yes |
| **deploy-custom-main.sh** | ~3-5 min | ~3 min | ~3 min | Each time (generate) | ⚠️ No |
| **update-main-image.sh** | N/A | ~30s | ❌ N/A | ❌ Never | N/A |

## Feature Comparison

| Feature | deploy-from-source | deploy-custom-main | update-main-image |
|---------|-------------------|-------------------|-------------------|
| Source code required | ✅ Yes | ❌ No | ❌ No |
| Local roxctl preferred | ✅ Yes | ⚠️ Optional | ❌ N/A |
| Chart modification | ✅ Yes | ❌ No | ❌ No |
| Full Helm control | ✅ Yes | ⚠️ Partial | ❌ No |
| Fastest initial deploy | ✅ Yes | ❌ No | N/A |
| Fastest updates | ⚠️ Good | ❌ No | ✅ Yes |
| Zero downtime updates | ✅ Yes | ✅ Yes | ✅ Yes |
| Rollback support | ✅ Helm | ✅ Helm | ✅ kubectl |
| Config preservation | ✅ Excellent | ⚠️ With reuse-values | ❌ N/A |

## Recommended Workflows

### Workflow 1: Active StackRox Development (Optimal)

```bash
# Day 1: Setup
cd ~/stackrox  # Source code directory
./deploy-from-source.sh abc123 4.6.x-nightly-20241003
# Time: ~1 minute

# Day 2-30: Code iterations
# Build, tag, push image
make image
docker tag ... localhost:5001/stackrox/main:abc124
docker push localhost:5001/stackrox/main:abc124

# Fast update
./update-main-image.sh abc124
# Time: ~30 seconds

# Or with Helm (if you need to change other values)
helm upgrade stackrox-central-services \
  ./helm-output/stackrox-central-services-chart/ \
  --reuse-values --set image.tag=abc124
# Time: ~10 seconds
```

**Total time per iteration**: ~5-10 minutes (build) + ~30 seconds (deploy)

---

### Workflow 2: Custom Image + Nightlies (Without Source)

```bash
# Day 1: Initial deployment
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
# Time: ~3-5 minutes

# Day 2-30: Image iterations
./update-main-image.sh abc124
./update-main-image.sh abc125
# Time: ~30 seconds each

# Week 2: Update nightly components
export HELM_REUSE_VALUES=true
./deploy-custom-main.sh abc125 4.6.x-nightly-20241010
# Time: ~3 minutes
```

**Total time per iteration**: ~5-10 minutes (build) + ~30 seconds (deploy)

---

### Workflow 3: Testing Chart Changes (Source Required)

```bash
# Edit chart templates
vim image/templates/helm/stackrox-central/templates/deployment.yaml.htpl

# Render updated chart
roxctl helm output central-services \
  --output-dir ./test-charts \
  --debug

# Deploy test
helm upgrade --install test-central \
  ./test-charts/stackrox-central-services-chart/ \
  --namespace test-stackrox \
  --create-namespace \
  --values my-test-values.yaml

# Iterate
# Edit → Render → Deploy → Test → Repeat
```

**Time per iteration**: ~10-20 seconds (render + deploy)

---

### Workflow 4: CI/CD Pipeline

```bash
#!/usr/bin/env bash
# ci-deploy.sh

GIT_SHA="$1"
NIGHTLY_TAG="$2"

# Build image
make image
docker tag ... localhost:5001/stackrox/main:$GIT_SHA
docker push localhost:5001/stackrox/main:$GIT_SHA

# Check if deployment exists
if kubectl get deployment central -n stackrox &>/dev/null; then
  # Fast update (no roxctl)
  ./update-main-image.sh "$GIT_SHA"
else
  # Initial deployment
  if [[ -d "image/templates/helm" ]]; then
    # Have source - use faster method
    ./deploy-from-source.sh "$GIT_SHA" "$NIGHTLY_TAG"
  else
    # No source - use standard method
    ./deploy-custom-main.sh "$GIT_SHA" "$NIGHTLY_TAG"
  fi
fi

# Run tests
kubectl wait --for=condition=ready pod -l app=central -n stackrox --timeout=5m
./run-integration-tests.sh
```

---

## When Each Method is Best

### Use deploy-from-source.sh when:
* ✅ You're a StackRox developer with source code
* ✅ You're testing chart template changes
* ✅ You want the fastest possible deployment
* ✅ You need full control over Helm values
* ✅ You'll be deploying frequently

### Use deploy-custom-main.sh when:
* ✅ You don't have source code access
* ✅ You're deploying custom-built images
* ✅ You want a simple script interface
* ✅ You're okay with slightly slower deployments
* ✅ You're using it in CI/CD without source

### Use update-main-image.sh when:
* ✅ You're iterating on code changes (any deployment method)
* ✅ You need the absolute fastest updates
* ✅ You only need to change image tags
* ✅ You want zero downtime
* ✅ You want instant rollback capability

### Use direct Helm commands when:
* ✅ You have a pre-rendered chart
* ✅ You need maximum flexibility
* ✅ You're making complex configuration changes
* ✅ You want to manage releases manually

## Migration Between Methods

### From deploy-custom-main.sh to deploy-from-source.sh

```bash
# If you already deployed with deploy-custom-main.sh:

# 1. Clone source code
git clone https://github.com/stackrox/stackrox.git ~/stackrox
cd ~/stackrox

# 2. Delete existing deployment (or keep and update in place)
kubectl delete namespace stackrox

# 3. Deploy from source
./deploy-from-source.sh abc123 4.6.x-nightly-20241003

# Now you can update faster with Helm reuse
```

### From deploy-from-source.sh to deploy-custom-main.sh

```bash
# If you lose access to source code:

# The deployed Helm release works the same
# For updates, use update-main-image.sh

# For full redeployment:
./deploy-custom-main.sh abc124 4.6.x-nightly-20241003
```

## Cost Analysis

### Development Time Cost

**Using deploy-custom-main.sh**:
* Initial setup: 5 minutes
* Per update: 30 seconds (with update-main-image.sh)
* 20 updates/day × 30 seconds = 10 minutes/day

**Using deploy-from-source.sh**:
* Initial setup: 1 minute
* Per update: 10 seconds (Helm) or 30 seconds (kubectl)
* 20 updates/day × 10 seconds = 3.3 minutes/day

**Time saved**: ~7 minutes/day per developer
**Over a year**: ~30 hours per developer

### Infrastructure Cost

Both methods use the same deployed resources. No difference in runtime costs.

## Summary

| Priority | Recommended Method | Why |
|----------|-------------------|-----|
| **Fastest initial deploy** | deploy-from-source.sh | ~1 min vs ~3-5 min |
| **Fastest updates** | update-main-image.sh | ~30s, works with any method |
| **Most flexible** | deploy-from-source.sh + Helm | Full chart control |
| **Easiest setup** | deploy-custom-main.sh | No source required |
| **Best for production** | Any + update-main-image.sh | Zero downtime updates |
| **Best for development** | deploy-from-source.sh | Faster iteration |

**Our recommendation**:
1. If you have source code: **Use deploy-from-source.sh**
2. For all image updates: **Use update-main-image.sh**
3. For config updates: **Use Helm with the rendered chart**
