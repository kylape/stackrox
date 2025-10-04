# Deploying with Custom Main Image and Nightly Builds

This guide explains how to deploy StackRox with a custom `main` image while using nightly builds for all other components.

## Use Case

You have a local development branch built as `localhost:5000/stackrox/main:abc123` and want to deploy it with production-quality components (central-db, scanner, etc.) from the nightly builds at `quay.io/rhacs-eng`.

## Prerequisites

1. **Local Registry**: Ensure your custom image is pushed to `localhost:5000`
   ```bash
   # Example: Build and push your custom main image
   make image
   docker tag stackrox/main:$(make tag) localhost:5000/stackrox/main:abc123
   docker push localhost:5000/stackrox/main:abc123
   ```

2. **Quay.io Credentials**: You need credentials for `quay.io/rhacs-eng` registry
   * Contact your team admin for access
   * Or use robot account credentials

3. **Kubernetes/OpenShift Cluster**: Access to a cluster (local or remote)

## Quick Start

### Full Deployment (Central + Sensor)

```bash
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

The script will:
1. Prompt for quay.io credentials (if not set)
2. Configure custom main image: `localhost:5000/stackrox/main:abc123`
3. Configure nightly images: `quay.io/rhacs-eng/<component>:4.6.x-nightly-20241003`
4. Set deployment method to Helm (default)
5. Confirm deployment settings
6. Deploy using the platform-appropriate `deploy-local.sh`

### Environment Variables

Set these to skip prompts:

```bash
export REGISTRY_USERNAME="your-quay-username"
export REGISTRY_PASSWORD="your-quay-password"
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Platform Selection

Auto-detected by default. Override with:

```bash
PLATFORM=openshift ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
# or
PLATFORM=k8s ./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

## Advanced Usage

### Deploy Only Central

```bash
# Set environment variables
export MAIN_IMAGE="localhost:5000/stackrox/main:abc123"
export CENTRAL_DB_IMAGE="quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003"
export SCANNER_IMAGE="quay.io/rhacs-eng/scanner:4.6.x-nightly-20241003"
export SCANNER_DB_IMAGE="quay.io/rhacs-eng/scanner-db:4.6.x-nightly-20241003"
export ROXCTL_IMAGE="quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003"
export USE_LOCAL_ROXCTL=false

export REGISTRY_USERNAME="your-username"
export REGISTRY_PASSWORD="your-password"

# Deploy Central only
./deploy/k8s/central.sh
```

### Deploy Only Sensor

First, ensure Central is deployed. Then:

```bash
export MAIN_IMAGE="localhost:5000/stackrox/main:abc123"
export CLUSTER="my-test-cluster"
export REGISTRY_USERNAME="your-username"
export REGISTRY_PASSWORD="your-password"

# Deploy Sensor
./deploy/k8s/sensor.sh
```

### Use kubectl Instead of Helm

Helm is the default. To use kubectl manifests instead:

```bash
export OUTPUT_FORMAT=kubectl
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Enable Monitoring

```bash
export MONITORING_SUPPORT=true
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

### Use Persistent Storage

```bash
export STORAGE=pvc
export STORAGE_SIZE=20
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

## Finding Nightly Build Tags

Check quay.io/rhacs-eng for available tags:

```bash
# Using curl (requires authentication)
curl -H "Authorization: Bearer $(echo -n '$REGISTRY_USERNAME:$REGISTRY_PASSWORD' | base64)" \
     https://quay.io/api/v1/repository/rhacs-eng/main/tag/

# Or browse: https://quay.io/repository/rhacs-eng/main?tab=tags
```

Common patterns:
* `4.6.x-nightly-20241003` - Nightly build from Oct 3, 2024
* `4.6.0-rc.1` - Release candidate
* `latest` - Latest nightly (not recommended for reproducibility)

## Configuration Details

### Images Configured

| Component | Custom Config | Nightly Config |
|-----------|---------------|----------------|
| Main | `localhost:5000/stackrox/main:abc123` | - |
| Central DB | - | `quay.io/rhacs-eng/central-db:nightly-tag` |
| Scanner | - | `quay.io/rhacs-eng/scanner:nightly-tag` |
| Scanner DB | - | `quay.io/rhacs-eng/scanner-db:nightly-tag` |
| Scanner V4 | - | `quay.io/rhacs-eng/scanner-v4:nightly-tag` |
| Scanner V4 DB | - | `quay.io/rhacs-eng/scanner-v4-db:nightly-tag` |
| roxctl | - | `quay.io/rhacs-eng/roxctl:nightly-tag` |

### Environment Variables Set

The script automatically configures:

```bash
# Custom main image
MAIN_IMAGE_REPO="localhost:5000/stackrox/main"
MAIN_IMAGE_TAG="abc123"
MAIN_IMAGE="localhost:5000/stackrox/main:abc123"

# Nightly build registry
DEFAULT_IMAGE_REGISTRY="quay.io/rhacs-eng"

# Component images
CENTRAL_DB_IMAGE="quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003"
SCANNER_IMAGE="quay.io/rhacs-eng/scanner:4.6.x-nightly-20241003"
SCANNER_DB_IMAGE="quay.io/rhacs-eng/scanner-db:4.6.x-nightly-20241003"
ROXCTL_IMAGE="quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003"

# Registry authentication
REGISTRY_USERNAME="your-username"
REGISTRY_PASSWORD="your-password"

# Deployment settings
OUTPUT_FORMAT=helm  # Use Helm deployment (default)
SENSOR_HELM_DEPLOY=true  # Use Helm for Sensor (default)
LOCAL_DEPLOYMENT=true
USE_LOCAL_ROXCTL=false  # Use Docker-based roxctl
COLLECTION_METHOD=core_bpf
MONITORING_SUPPORT=false
POD_SECURITY_POLICIES=false
```

## Troubleshooting

### Pull Secret Issues

If you see `ImagePullBackOff` errors for quay.io images:

1. **Verify credentials**:
   ```bash
   docker login quay.io/rhacs-eng
   # Enter your username and password
   ```

2. **Check secret creation**:
   ```bash
   kubectl get secret -n stackrox
   # Look for pull secrets
   ```

3. **Manual secret creation**:
   ```bash
   kubectl create secret docker-registry quay-pull-secret \
     --docker-server=quay.io \
     --docker-username="$REGISTRY_USERNAME" \
     --docker-password="$REGISTRY_PASSWORD" \
     -n stackrox
   ```

### Local Registry Connection Issues

If Central can't pull from `localhost:5000`:

1. **Verify registry is accessible from cluster**:
   ```bash
   # For kind clusters
   docker exec kind-control-plane curl -v http://localhost:5000/v2/

   # For other clusters, the registry must be network-accessible
   ```

2. **For kind, use host.docker.internal**:
   ```bash
   export MAIN_IMAGE_REPO="host.docker.internal:5000/stackrox/main"
   ```

3. **For remote clusters**, push to a registry accessible from the cluster:
   ```bash
   docker tag localhost:5000/stackrox/main:abc123 quay.io/your-repo/main:abc123
   docker push quay.io/your-repo/main:abc123
   export MAIN_IMAGE="quay.io/your-repo/main:abc123"
   ```

### roxctl Version Mismatch

The script sets `USE_LOCAL_ROXCTL=false` to use Docker-based roxctl. If you see roxctl errors:

```bash
# Explicitly pull the roxctl image
docker pull quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003

# Or use local roxctl if version compatible
export USE_LOCAL_ROXCTL=true
roxctl version
```

### Helm vs kubectl Issues

If deployment fails with Helm:

```bash
# Force kubectl deployment
export OUTPUT_FORMAT=kubectl
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
```

## Cleanup

To remove the deployment:

```bash
# Delete Central namespace
kubectl delete namespace stackrox

# Or if using custom namespace
kubectl delete namespace $CENTRAL_NAMESPACE
```

## Next Steps

After deployment:

1. **Access Central UI**:
   ```bash
   # Check the endpoint
   kubectl get svc -n stackrox central

   # Port-forward if needed
   kubectl port-forward -n stackrox svc/central 8000:443

   # Open browser
   open https://localhost:8000
   ```

2. **Get admin password**:
   ```bash
   cat deploy/k8s/central-deploy/password
   # Username: admin
   ```

3. **Verify images**:
   ```bash
   kubectl get pods -n stackrox -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.containers[*]}{"\t"}{.image}{"\n"}{end}{end}'
   ```

4. **Check logs**:
   ```bash
   kubectl logs -n stackrox deployment/central -c central
   ```
