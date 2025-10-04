# roxctl Usage in Helm Deployments

## Why roxctl is Still Used

Even when using Helm deployments (`OUTPUT_FORMAT=helm`), roxctl is still required for **Central deployment only**. Here's why:

### Central Deployment with Helm

```bash
# What happens when you run:
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

# Behind the scenes (common/k8sbased.sh:284-294):
roxctl central generate kubernetes \
  --output-format helm \
  -i localhost:5000/stackrox/main:abc123 \
  --central-db-image quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003 \
  --scanner-image quay.io/rhacs-eng/scanner:4.6.x-nightly-20241003
  # ... generates Helm chart in central-deploy/chart/

# Then:
helm upgrade --install stackrox-central-services central-deploy/chart/
```

**Why?** The Helm chart must match the component versions you're deploying. roxctl generates a version-specific chart that's compatible with the nightly images.

### Sensor Deployment with Helm

**No roxctl needed!** Sensor downloads the chart directly from Central (`common/k8sbased.sh:696-699`):

```bash
# What happens:
curl "$CENTRAL_API/api/extensions/helm-charts/secured-cluster-services.zip"
unzip secured-cluster-services.zip
helm upgrade --install stackrox-secured-cluster-services ./chart/
```

Central provides a chart that's guaranteed to be compatible with itself.

## roxctl Version Compatibility

The scripts handle roxctl version selection (`common/k8sbased.sh:160-189`):

```bash
# Uses local roxctl if version matches image tag
if [[ "$USE_LOCAL_ROXCTL" == "true" ]] && roxctl version matches $MAIN_IMAGE_TAG; then
    use local roxctl
else
    # Use Docker-based roxctl with matching version
    docker run $ROXCTL_IMAGE central generate ...
fi
```

With your custom scripts setting `USE_LOCAL_ROXCTL=true`, it will:
1. Check if local roxctl version matches `$NIGHTLY_TAG`
2. If yes: use local roxctl
3. If no: fall back to Docker-based roxctl with `ROXCTL_IMAGE=quay.io/rhacs-eng/roxctl:$NIGHTLY_TAG`

## Options to Minimize roxctl Usage

### Option 1: Sensor-Only Updates (Zero roxctl)

If Central is already deployed, update just Sensor without roxctl:

```bash
# Initial deployment (requires roxctl for Central)
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Later: Update just Sensor (no roxctl needed)
./deploy-custom-sensor.sh abc124 my-cluster
```

Sensor deployment uses the chart from Central's API, no roxctl required.

### Option 2: Image-Only Updates (Zero roxctl)

Use `update-main-image.sh` to update images without regenerating charts:

```bash
# Initial deployment (requires roxctl once)
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

# Update just the image (no roxctl)
./update-main-image.sh abc124
```

This uses `kubectl set image`, bypassing Helm and roxctl entirely.

### Option 3: Pre-generate Chart, Update via Helm Values

Generate the chart once, then update only values:

```bash
# Step 1: Initial deployment (roxctl generates chart)
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

# Step 2: Update image via Helm values (no roxctl)
helm upgrade stackrox-central-services \
  ./deploy/k8s/central-deploy/chart/ \
  --namespace stackrox \
  --reuse-values \
  --set image.tag=abc124 \
  --set imagePullSecrets[0].name=stackrox

# The chart from step 1 is reused, only values change
```

### Option 4: Use Official Chart Repository (Released Versions Only)

If you're using released versions (not nightlies), skip roxctl entirely:

```bash
# Add official Helm repo
helm repo add rhacs https://mirror.openshift.com/pub/rhacs/charts/

# Deploy with custom values
helm upgrade --install stackrox-central-services \
  rhacs/stackrox-central-services \
  --version 4.6.0 \
  --namespace stackrox \
  --set image.registry=localhost:5000 \
  --set image.name=stackrox/main \
  --set image.tag=abc123
```

**Limitation**: Official repo only has released versions, not nightly builds.

### Option 5: Extract Chart from roxctl Image (Advanced)

Pre-extract the chart template from roxctl image:

```bash
# Extract chart templates from roxctl (one-time)
docker run --rm \
  -v $(pwd)/chart-templates:/output \
  quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003 \
  central generate kubernetes \
  --output-format helm \
  --output-dir /output

# Deploy using extracted templates (no roxctl)
helm upgrade --install stackrox-central-services \
  ./chart-templates/chart/ \
  --namespace stackrox \
  --set image.tag=abc123
```

**Limitation**: Chart must be compatible with your image versions.

## Recommended Workflow for Custom Builds

### For Iterative Development (Minimal roxctl)

```bash
# Day 1: Initial deployment (roxctl required once)
./deploy-custom-main.sh v1 4.6.x-nightly-20241003

# Day 2-30: Image updates (zero roxctl)
./update-main-image.sh v2
./update-main-image.sh v3
./update-main-image.sh v4
# ...

# When you need to update nightly versions:
export HELM_REUSE_VALUES=true
./deploy-custom-central.sh v4 4.6.x-nightly-20241010
```

### For CI/CD (Controlled roxctl Usage)

```bash
#!/usr/bin/env bash
# ci-deploy.sh

GIT_SHA="$1"
NIGHTLY_TAG="$2"

# Check if Central exists
if kubectl get deployment central -n stackrox &>/dev/null; then
  # Central exists - update without roxctl
  ./update-main-image.sh "$GIT_SHA"
else
  # Initial deployment - requires roxctl
  ./deploy-custom-main.sh "$GIT_SHA" "$NIGHTLY_TAG"
fi
```

## Why Not Completely Remove roxctl?

### Technical Reasons

1. **Chart Generation**: roxctl bundles the correct Helm chart for specific versions
2. **Version Compatibility**: Charts have version-specific CRDs and templates
3. **Image References**: roxctl injects correct image references into charts
4. **Platform Detection**: roxctl applies platform-specific configurations (K8s vs OpenShift)

### What roxctl Actually Generates

When you run `roxctl central generate`:

```
central-deploy/
├── chart/                       # Helm chart
│   ├── Chart.yaml              # Chart metadata
│   ├── values-public.yaml      # Default values
│   ├── values-private.yaml     # Generated secrets/passwords
│   ├── templates/              # Kubernetes manifests as templates
│   │   ├── central-deployment.yaml
│   │   ├── central-db-deployment.yaml
│   │   ├── scanner-deployment.yaml
│   │   ├── scanner-v4-deployment.yaml
│   │   ├── services.yaml
│   │   ├── configmaps.yaml
│   │   ├── secrets.yaml
│   │   └── ...
│   └── ...
├── password                    # Admin password
└── ...
```

This chart is version-specific and includes:
* Correct CRD versions
* Compatible API versions
* Version-specific features/flags
* Default resource configurations
* Platform-specific adjustments

### Can You Use a Generic Chart?

**For released versions**: Yes, use official Helm repository
**For nightly builds**: No, chart must match nightly API/features
**For custom builds**: No, chart must match component versions

## roxctl Performance Considerations

### Docker-based roxctl (Slower)

```bash
# What happens with USE_LOCAL_ROXCTL=false:
docker run --rm \
  quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003 \
  central generate kubernetes ...

# Time: ~10-30 seconds (image pull + generate)
```

### Local roxctl (Faster)

```bash
# What happens with USE_LOCAL_ROXCTL=true:
roxctl central generate kubernetes ...

# Time: ~1-5 seconds (generate only)
```

### One-Time Generation (Fastest for Updates)

```bash
# Initial: Generate chart once
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

# Updates: Reuse chart, update values only
helm upgrade stackrox-central-services \
  ./deploy/k8s/central-deploy/chart/ \
  --reuse-values \
  --set image.tag=abc124

# Time: ~1-3 seconds (Helm only)
```

## Summary: roxctl Usage by Deployment Type

| Deployment Type | roxctl for Central | roxctl for Sensor | Alternative |
|-----------------|-------------------|-------------------|-------------|
| Full deployment (initial) | ✅ Required | ❌ Not needed | None |
| Central update (Helm reuse) | ✅ Required | N/A | `update-main-image.sh` |
| Sensor update | N/A | ❌ Not needed | Always roxctl-free |
| Image-only update | ❌ Not needed | ❌ Not needed | `update-main-image.sh` |
| Released versions | ❌ Not needed | ❌ Not needed | Official Helm repo |
| Nightly builds | ✅ Required | ❌ Not needed | Pre-extract chart |

## Best Practice Recommendations

1. **For development iterations**: Use `update-main-image.sh` (zero roxctl after initial deployment)
2. **For initial deployment**: Accept roxctl requirement (one-time cost)
3. **For sensor updates**: Already roxctl-free by default
4. **Use local roxctl**: Set `USE_LOCAL_ROXCTL=true` if version compatible (faster)
5. **Cache generated charts**: Reuse chart directory for value-only updates

## Checking Your Current Setup

```bash
# Check if using Docker-based roxctl
grep USE_LOCAL_ROXCTL deploy-custom-central.sh
# If true: uses local roxctl (faster)
# If false: uses Docker roxctl (slower but version-matched)

# Check roxctl version
roxctl version

# Check if compatible with nightly tag
NIGHTLY_TAG="4.6.x-nightly-20241003"
roxctl version | grep "$NIGHTLY_TAG"
# If matches: can use USE_LOCAL_ROXCTL=true
# If not: should use Docker-based roxctl
```

## Conclusion

**roxctl is required for Central deployment** because it generates version-specific Helm charts. However, you can minimize its usage by:

1. Using `update-main-image.sh` for frequent image updates
2. Using `HELM_REUSE_VALUES=true` for configuration updates
3. Leveraging the roxctl-free Sensor deployment
4. Pre-generating charts when possible

The custom scripts already optimize roxctl usage - it's only invoked when absolutely necessary (initial Central deployment or component version changes).
