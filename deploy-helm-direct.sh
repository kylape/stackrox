#!/usr/bin/env bash
set -euo pipefail

# Deploy StackRox Central using Helm directly without roxctl
#
# This script deploys Central using the official Helm chart repository
# instead of generating charts with roxctl.
#
# Usage:
#   ./deploy-helm-direct.sh [CUSTOM_MAIN_TAG] [NIGHTLY_TAG] [CHART_VERSION]
#
# Example:
#   ./deploy-helm-direct.sh abc123 4.6.x-nightly-20241003 4.6.0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
CUSTOM_MAIN_TAG="${1:-}"
NIGHTLY_TAG="${2:-}"
CHART_VERSION="${3:-4.6.0}"

if [[ -z "$CUSTOM_MAIN_TAG" ]]; then
    echo "Error: Custom main image tag required"
    echo "Usage: $0 CUSTOM_MAIN_TAG NIGHTLY_TAG [CHART_VERSION]"
    echo "Example: $0 abc123 4.6.x-nightly-20241003 4.6.0"
    exit 1
fi

if [[ -z "$NIGHTLY_TAG" ]]; then
    echo "Error: Nightly tag required"
    echo "Usage: $0 CUSTOM_MAIN_TAG NIGHTLY_TAG [CHART_VERSION]"
    echo "Example: $0 abc123 4.6.x-nightly-20241003 4.6.0"
    exit 1
fi

echo "============================================="
echo "Direct Helm Deployment (No roxctl)"
echo "============================================="
echo ""
echo "Custom main image tag: $CUSTOM_MAIN_TAG"
echo "Nightly builds tag: $NIGHTLY_TAG"
echo "Helm chart version: $CHART_VERSION"
echo ""

# Detect platform
source "${SCRIPT_DIR}/deploy/detect.sh"
if is_openshift; then
    PLATFORM="openshift"
else
    PLATFORM="k8s"
fi

echo "Platform: $PLATFORM"

# Namespace
NAMESPACE="${CENTRAL_NAMESPACE:-stackrox}"

# Prompt for registry credentials if not set
if [[ -z "${REGISTRY_USERNAME:-}" ]]; then
    read -p "Quay.io username: " REGISTRY_USERNAME
fi

if [[ -z "${REGISTRY_PASSWORD:-}" ]]; then
    read -sp "Quay.io password: " REGISTRY_PASSWORD
    echo ""
fi

echo ""
echo "============================================="
echo "Configuration"
echo "============================================="
echo ""

# Image configuration
MAIN_IMAGE="localhost:5000/stackrox/main:${CUSTOM_MAIN_TAG}"
CENTRAL_DB_IMAGE="quay.io/rhacs-eng/central-db:${NIGHTLY_TAG}"
SCANNER_IMAGE="quay.io/rhacs-eng/scanner:${NIGHTLY_TAG}"
SCANNER_DB_IMAGE="quay.io/rhacs-eng/scanner-db:${NIGHTLY_TAG}"
SCANNER_V4_IMAGE="quay.io/rhacs-eng/scanner-v4:${NIGHTLY_TAG}"
SCANNER_V4_DB_IMAGE="quay.io/rhacs-eng/scanner-v4-db:${NIGHTLY_TAG}"

echo "Images:"
echo "  Main:         $MAIN_IMAGE"
echo "  Central-DB:   $CENTRAL_DB_IMAGE"
echo "  Scanner:      $SCANNER_IMAGE"
echo "  Scanner-DB:   $SCANNER_DB_IMAGE"
echo "  Scanner-V4:   $SCANNER_V4_IMAGE"
echo "  Scanner-V4-DB: $SCANNER_V4_DB_IMAGE"
echo ""

# Create namespace if needed
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Create pull secret for quay.io
echo "Creating pull secret..."
kubectl create secret docker-registry stackrox \
    --docker-server=quay.io \
    --docker-username="$REGISTRY_USERNAME" \
    --docker-password="$REGISTRY_PASSWORD" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# Add StackRox Helm repository
echo ""
echo "Adding StackRox Helm repository..."
helm repo add rhacs https://mirror.openshift.com/pub/rhacs/charts/
helm repo update

# Create values file
VALUES_FILE=$(mktemp)
trap "rm -f $VALUES_FILE" EXIT

cat > "$VALUES_FILE" <<EOF
# Custom image configuration
image:
  registry: localhost:5000
  name: stackrox/main
  tag: ${CUSTOM_MAIN_TAG}

imagePullSecrets:
  - name: stackrox

# Central DB configuration
central:
  db:
    enabled: true
    image:
      registry: quay.io
      name: rhacs-eng/central-db
      tag: ${NIGHTLY_TAG}

  # Resource limits for local dev
  resources:
    requests:
      memory: 1Gi
      cpu: 500m
    limits:
      memory: 4Gi
      cpu: 1

  persistence:
    none: true

# Scanner configuration
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

# Scanner V4 configuration
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

# Environment configuration
env:
  openshift: $([ "$PLATFORM" = "openshift" ] && echo "4" || echo "null")

# Allow non-standard namespace
allowNonstandardNamespace: true

# Disable telemetry for local dev
central:
  telemetry:
    enabled: false
EOF

echo ""
echo "Values file created:"
cat "$VALUES_FILE"
echo ""

# Confirm deployment
read -p "Proceed with Helm deployment? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 0
fi

echo ""
echo "============================================="
echo "Deploying with Helm"
echo "============================================="
echo ""

# Deploy with Helm
helm upgrade --install stackrox-central-services \
    rhacs/stackrox-central-services \
    --version "$CHART_VERSION" \
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
echo "Retrieving admin password..."
ADMIN_PASSWORD=$(kubectl get secret -n "$NAMESPACE" central-htpasswd -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || echo "not-yet-available")

echo ""
echo "Access Information:"
echo "  Namespace: $NAMESPACE"
echo "  Username: admin"
echo "  Password: $ADMIN_PASSWORD"
echo ""
echo "Port forward to access:"
echo "  kubectl port-forward -n $NAMESPACE svc/central 8000:443"
echo "  open https://localhost:8000"
echo ""
echo "View deployment:"
echo "  helm list -n $NAMESPACE"
echo "  kubectl get pods -n $NAMESPACE"
echo ""
