# Quick Reference: Custom Main Image Deployment

## Scripts Available

| Script | Purpose | Usage |
|--------|---------|-------|
| `deploy-custom-main.sh` | Full deployment (Central + Sensor) | `./deploy-custom-main.sh <tag> <nightly>` |
| `deploy-custom-central.sh` | Central only | `./deploy-custom-central.sh <tag> <nightly>` |
| `deploy-custom-sensor.sh` | Sensor only | `./deploy-custom-sensor.sh <tag> <cluster-name>` |
| `deploy-from-source.sh` | Deploy using source charts (faster) | `./deploy-from-source.sh <tag> <nightly>` |
| `update-main-image.sh` | Zero-downtime image update | `./update-main-image.sh <new-tag> [namespace]` |

## Quick Start Examples

### Full Deployment
```bash
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Central Only
```bash
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

### Sensor Only (requires Central already deployed)
```bash
./deploy-custom-sensor.sh abc123 my-cluster
```

### Deploy from Source (Fastest, requires source code)
```bash
./deploy-from-source.sh abc123 4.6.x-nightly-20241003
```

### Update Existing Deployment (Zero Downtime)
```bash
# Rolling update to new image tag
./update-main-image.sh xyz789
```

## Environment Variables Cheat Sheet

### Required (or will prompt)
```bash
export REGISTRY_USERNAME="quay-username"
export REGISTRY_PASSWORD="quay-password"
```

### Optional Overrides
```bash
# Platform selection
export PLATFORM=k8s          # or openshift

# Deployment mode
export LOCAL_DEPLOYMENT=true # or false

# Output format (helm is default)
export OUTPUT_FORMAT=helm    # or kubectl
export SENSOR_HELM_DEPLOY=true  # or false (for sensor)

# Monitoring
export MONITORING_SUPPORT=true

# Storage
export STORAGE=pvc
export STORAGE_SIZE=50

# Collection method
export COLLECTION_METHOD=core_bpf

# Custom namespace
export CENTRAL_NAMESPACE=custom-ns
export SENSOR_NAMESPACE=custom-ns

# Hot reload
export ROX_HOTRELOAD=true

# Scanner V4
export ROX_SCANNER_V4=true  # or false
```

## One-Liners

### Deploy with monitoring and persistent storage
```bash
MONITORING_SUPPORT=true STORAGE=pvc STORAGE_SIZE=20 \
  ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Deploy using kubectl instead of Helm
```bash
# kubectl manifests instead of Helm (Helm is default)
OUTPUT_FORMAT=kubectl ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Deploy to OpenShift with route exposure
```bash
PLATFORM=openshift LOAD_BALANCER=route \
  ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Deploy with hot-reload enabled
```bash
ROX_HOTRELOAD=true LOCAL_DEPLOYMENT=true \
  ./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

## Manual Configuration (without scripts)

If you prefer to set everything manually:

```bash
# Set custom main image
export MAIN_IMAGE="localhost:5000/stackrox/main:abc123"

# Set nightly images
export CENTRAL_DB_IMAGE="quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003"
export SCANNER_IMAGE="quay.io/rhacs-eng/scanner:4.6.x-nightly-20241003"
export SCANNER_DB_IMAGE="quay.io/rhacs-eng/scanner-db:4.6.x-nightly-20241003"
export ROXCTL_IMAGE="quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003"

# Set credentials
export REGISTRY_USERNAME="your-username"
export REGISTRY_PASSWORD="your-password"
export USE_LOCAL_ROXCTL=false

# Deploy
./deploy/k8s/deploy-local.sh
```

## Common Issues & Quick Fixes

### ImagePullBackOff for quay.io images
```bash
# Test credentials
docker login quay.io -u "$REGISTRY_USERNAME" -p "$REGISTRY_PASSWORD"

# Check secret in cluster
kubectl get secret -n stackrox
```

### Local registry not accessible
```bash
# For kind clusters
export MAIN_IMAGE_REPO="host.docker.internal:5000/stackrox/main"

# Verify registry is running
curl -v http://localhost:5000/v2/
```

### roxctl version mismatch
```bash
# Force Docker-based roxctl
export USE_LOCAL_ROXCTL=false

# Or pull specific version
docker pull quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003
```

## Access Deployed Central

```bash
# Get admin password
cat deploy/k8s/central-deploy/password

# Port forward
kubectl port-forward -n stackrox svc/central 8000:443

# Open browser
open https://localhost:8000
# Username: admin
# Password: (from password file)
```

## Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n stackrox

# Verify image versions
kubectl get pods -n stackrox -o jsonpath='{range .items[*]}{"\n"}{.metadata.name}{"\n"}{range .spec.containers[*]}{"\t"}{.image}{"\n"}{end}{end}'

# Check Central logs
kubectl logs -n stackrox deployment/central -c central --tail=50

# Check Sensor logs
kubectl logs -n stackrox deployment/sensor -c sensor --tail=50
```

## Updating Existing Deployments

### Zero-Downtime Rolling Update (Recommended)
```bash
# Update to new image tag with zero downtime
./update-main-image.sh xyz789

# Or specify namespace
./update-main-image.sh xyz789 stackrox
```

This performs a rolling update of Central, Sensor, Admission Controller, and Collector without:
* Regenerating certificates
* Recreating secrets
* Causing service interruption

### Update via Helm (Preserves Config)
```bash
export HELM_REUSE_VALUES=true
OUTPUT_FORMAT=helm ./deploy-custom-central.sh xyz789 4.6.x-nightly-20241003
```

### Manual Component Update
```bash
# Update just Central
kubectl set image deployment/central central=localhost:5000/stackrox/main:xyz789 -n stackrox
kubectl rollout status deployment/central -n stackrox

# Rollback if needed
kubectl rollout undo deployment/central -n stackrox
```

## Cleanup

```bash
# Delete everything
kubectl delete namespace stackrox

# Or keep data with PVC
kubectl delete deployment,service,configmap,secret -n stackrox --all
```

## Finding Nightly Tags

```bash
# List recent tags (requires auth)
curl -s -H "Authorization: Bearer $(echo -n "$REGISTRY_USERNAME:$REGISTRY_PASSWORD" | base64)" \
  'https://quay.io/api/v1/repository/rhacs-eng/main/tag/?limit=10' | jq -r '.tags[].name'

# Or browse: https://quay.io/repository/rhacs-eng/main?tab=tags
```

## Advanced Configurations

### Deploy with custom TLS certificates
```bash
export ROX_DEFAULT_TLS_CERT_FILE=/path/to/cert.pem
export ROX_DEFAULT_TLS_KEY_FILE=/path/to/key.pem
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

### Deploy with trusted CA bundle
```bash
export TRUSTED_CA_FILE=/path/to/ca-bundle.pem
./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

### Deploy with custom Helm values
```bash
export ROX_CENTRAL_EXTRA_HELM_VALUES_FILE=/path/to/custom-values.yaml
OUTPUT_FORMAT=helm ./deploy-custom-central.sh abc123 4.6.x-nightly-20241003
```

### Use different nightly tags for different components
```bash
export MAIN_IMAGE="localhost:5000/stackrox/main:abc123"
export CENTRAL_DB_IMAGE="quay.io/rhacs-eng/central-db:4.6.0-rc.1"
export SCANNER_IMAGE="quay.io/rhacs-eng/scanner:4.5.x-nightly-20240901"
export SCANNER_DB_IMAGE="quay.io/rhacs-eng/scanner-db:4.5.x-nightly-20240901"
export ROXCTL_IMAGE="quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003"
export REGISTRY_USERNAME="username"
export REGISTRY_PASSWORD="password"
./deploy/k8s/deploy-local.sh
```
