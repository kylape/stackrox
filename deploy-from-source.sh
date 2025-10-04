#!/usr/bin/env bash
set -euo pipefail

# Deploy StackRox using Helm charts from source code (no roxctl generation)
#
# This uses the source code's Helm chart templates directly via roxctl helm output,
# which is much faster than roxctl central generate.
#
# Usage:
#   ./deploy-from-source.sh [CUSTOM_MAIN_TAG] [NIGHTLY_TAG]
#
# Example:
#   ./deploy-from-source.sh abc123 4.6.x-nightly-20241003

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
CUSTOM_MAIN_TAG="${1:-}"
NIGHTLY_TAG="${2:-}"

if [[ -z "$CUSTOM_MAIN_TAG" ]]; then
    echo "Error: Custom main image tag required"
    echo "Usage: $0 CUSTOM_MAIN_TAG [NIGHTLY_TAG]"
    echo "Example: $0 abc123 4.6.x-nightly-20241003"
    exit 1
fi

if [[ -z "$NIGHTLY_TAG" ]]; then
    echo "Error: Nightly tag required"
    echo "Usage: $0 CUSTOM_MAIN_TAG NIGHTLY_TAG"
    echo "Example: $0 abc123 4.6.x-nightly-20241003"
    exit 1
fi

echo "============================================="
echo "Deploy from Source (Faster Chart Rendering)"
echo "============================================="
echo ""
echo "Custom main image tag: $CUSTOM_MAIN_TAG"
echo "Nightly builds tag: $NIGHTLY_TAG"
echo ""

# Detect platform
source "${SCRIPT_DIR}/deploy/detect.sh"
if is_openshift; then
    PLATFORM="openshift"
    OPENSHIFT_VERSION="${ROX_OPENSHIFT_VERSION:-4}"
else
    PLATFORM="k8s"
fi

echo "Platform: $PLATFORM"

# Namespace
NAMESPACE="${CENTRAL_NAMESPACE:-stackrox}"

# Prompt for registry credentials if not set
if [[ -z "${REGISTRY_USERNAME:-}" ]]; then
    read -p "Quay.io username: " REGISTRY_USERNAME
    export REGISTRY_USERNAME
fi

if [[ -z "${REGISTRY_PASSWORD:-}" ]]; then
    read -sp "Quay.io password: " REGISTRY_PASSWORD
    echo ""
    export REGISTRY_PASSWORD
fi

echo ""
echo "Image Configuration:"

# Image configuration
MAIN_IMAGE="localhost:5001/stackrox/main:${CUSTOM_MAIN_TAG}"
CENTRAL_DB_IMAGE="quay.io/rhacs-eng/central-db:${NIGHTLY_TAG}"
SCANNER_IMAGE="quay.io/rhacs-eng/scanner:${NIGHTLY_TAG}"
SCANNER_DB_IMAGE="quay.io/rhacs-eng/scanner-db:${NIGHTLY_TAG}"
SCANNER_V4_IMAGE="quay.io/rhacs-eng/scanner-v4:${NIGHTLY_TAG}"
SCANNER_V4_DB_IMAGE="quay.io/rhacs-eng/scanner-v4-db:${NIGHTLY_TAG}"

echo "  Main:         $MAIN_IMAGE"
echo "  Central-DB:   $CENTRAL_DB_IMAGE"
echo "  Scanner:      $SCANNER_IMAGE"
echo "  Scanner-DB:   $SCANNER_DB_IMAGE"
echo "  Scanner-V4:   $SCANNER_V4_IMAGE"
echo "  Scanner-V4-DB: $SCANNER_V4_DB_IMAGE"
echo ""

# Create output directory
OUTPUT_DIR="${SCRIPT_DIR}/helm-output"
mkdir -p "$OUTPUT_DIR"

# Render Helm chart from source templates using roxctl
echo "============================================="
echo "Rendering Helm Chart from Source Templates"
echo "============================================="
echo ""
echo "Using: roxctl helm output (faster than roxctl central generate)"
echo ""

# Check if we have local roxctl
if command -v roxctl &>/dev/null; then
    ROXCTL_CMD="roxctl"
    echo "Using local roxctl: $(which roxctl)"
else
    echo "Local roxctl not found, using Docker-based roxctl"
    ROXCTL_CMD="docker run --rm -v ${OUTPUT_DIR}:/output quay.io/rhacs-eng/roxctl:${NIGHTLY_TAG}"
fi

# Render the chart from source templates
cd "$SCRIPT_DIR"

if [[ "$ROXCTL_CMD" == "roxctl" ]]; then
    # Local roxctl
    roxctl helm output central-services \
        --output-dir "$OUTPUT_DIR" \
        --image-defaults=development_build \
        --debug
else
    # Docker roxctl - need to handle volume mounting
    docker run --rm \
        -v "${SCRIPT_DIR}:/workspace" \
        -v "${OUTPUT_DIR}:/output" \
        -w /workspace \
        quay.io/rhacs-eng/roxctl:${NIGHTLY_TAG} \
        helm output central-services \
        --output-dir /output \
        --image-defaults=development_build \
        --debug
fi

echo ""
echo "Chart rendered to: $OUTPUT_DIR/stackrox-central-services-chart"
echo ""

# Create custom values file
VALUES_FILE="${OUTPUT_DIR}/custom-values.yaml"

cat > "$VALUES_FILE" <<EOF
# Custom image overrides
image:
  registry: localhost:5001
  name: stackrox/main
  tag: ${CUSTOM_MAIN_TAG}

imagePullSecrets:
  - name: stackrox

# Central DB
central:
  db:
    image:
      registry: quay.io
      name: rhacs-eng/central-db
      tag: ${NIGHTLY_TAG}

  # Local dev resources
  resources:
    requests:
      memory: 1Gi
      cpu: 500m
    limits:
      memory: 4Gi
      cpu: 1

  persistence:
    none: true

  telemetry:
    enabled: false

# Scanner V2
scanner:
  disable: false
  replicas: 1
  autoscaling:
    disable: true
  image:
    registry: quay.io
    name: rhacs-eng/scanner
    tag: ${NIGHTLY_TAG}
  dbImage:
    registry: quay.io
    name: rhacs-eng/scanner-db
    tag: ${NIGHTLY_TAG}
  resources:
    requests:
      memory: 500Mi
      cpu: 500m
    limits:
      memory: 2500Mi
      cpu: 2000m

# Scanner V4
scannerV4:
  disable: false
  indexer:
    replicas: 1
    autoscaling:
      disable: true
    image:
      registry: quay.io
      name: rhacs-eng/scanner-v4
      tag: ${NIGHTLY_TAG}
    resources:
      requests:
        memory: 1500Mi
        cpu: 400m
      limits:
        memory: 2Gi
        cpu: 1000m

  matcher:
    replicas: 1
    autoscaling:
      disable: true
    image:
      registry: quay.io
      name: rhacs-eng/scanner-v4
      tag: ${NIGHTLY_TAG}
    resources:
      requests:
        memory: 2Gi
        cpu: 400m
      limits:
        memory: 5500Mi
        cpu: 1000m

  db:
    image:
      registry: quay.io
      name: rhacs-eng/scanner-v4-db
      tag: ${NIGHTLY_TAG}
    resources:
      requests:
        memory: 2Gi
        cpu: 400m
      limits:
        memory: 2500Mi
        cpu: 1000m

# Environment
env:
  openshift: $([ "$PLATFORM" = "openshift" ] && echo "\"${OPENSHIFT_VERSION}\"" || echo "null")

allowNonstandardNamespace: true
EOF

echo "Custom values file created: $VALUES_FILE"
echo ""

# Create namespace and pull secret
echo "Creating namespace and pull secret..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret docker-registry stackrox \
    --docker-server=quay.io \
    --docker-username="$REGISTRY_USERNAME" \
    --docker-password="$REGISTRY_PASSWORD" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# Confirm deployment
read -p "Proceed with Helm deployment? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    echo ""
    echo "You can manually deploy later with:"
    echo "  helm upgrade --install stackrox-central-services \\"
    echo "    $OUTPUT_DIR/stackrox-central-services-chart \\"
    echo "    --namespace $NAMESPACE \\"
    echo "    --values $VALUES_FILE"
    exit 0
fi

echo ""
echo "============================================="
echo "Deploying with Helm"
echo "============================================="
echo ""

# Deploy with Helm
helm upgrade --install stackrox-central-services \
    "$OUTPUT_DIR/stackrox-central-services-chart" \
    --namespace "$NAMESPACE" \
    --values "$VALUES_FILE" \
    --wait \
    --timeout 10m

echo ""
echo "============================================="
echo "Deployment Complete!"
echo "============================================="
echo ""

# Get admin password
ADMIN_PASSWORD=$(kubectl get secret -n "$NAMESPACE" central-htpasswd -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || echo "not-yet-available")

echo "Access Information:"
echo "  Namespace: $NAMESPACE"
echo "  Username: admin"
echo "  Password: $ADMIN_PASSWORD"
echo ""
echo "Port forward:"
echo "  kubectl port-forward -n $NAMESPACE svc/central 8000:443"
echo "  open https://localhost:8000"
echo ""
echo "Helm release:"
echo "  helm list -n $NAMESPACE"
echo "  helm get values stackrox-central-services -n $NAMESPACE"
echo ""
echo "Chart location: $OUTPUT_DIR/stackrox-central-services-chart"
echo "Values file: $VALUES_FILE"
echo ""
echo "For updates with the same chart:"
echo "  helm upgrade stackrox-central-services \\"
echo "    $OUTPUT_DIR/stackrox-central-services-chart \\"
echo "    --namespace $NAMESPACE \\"
echo "    --reuse-values \\"
echo "    --set image.tag=new-tag"
echo ""
