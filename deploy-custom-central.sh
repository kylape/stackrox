#!/usr/bin/env bash
set -euo pipefail

# Deploy only StackRox Central with custom main image and nightly builds
#
# Usage:
#   ./deploy-custom-central.sh [CUSTOM_MAIN_TAG] [NIGHTLY_TAG]
#
# Example:
#   ./deploy-custom-central.sh abc123 4.6.x-nightly-20241003

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
echo "Custom StackRox Central Deployment"
echo "============================================="
echo ""
echo "Custom main image tag: $CUSTOM_MAIN_TAG"
echo "Nightly builds tag: $NIGHTLY_TAG"
echo ""

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

# Configure image repositories and tags
echo ""
echo "Configuring image references..."
echo ""

# Custom main image from local registry
export MAIN_IMAGE_REPO="localhost:5000/stackrox/main"
export MAIN_IMAGE_TAG="$CUSTOM_MAIN_TAG"
export MAIN_IMAGE="${MAIN_IMAGE_REPO}:${MAIN_IMAGE_TAG}"

# All other images from quay.io/rhacs-eng nightly builds
export DEFAULT_IMAGE_REGISTRY="quay.io/rhacs-eng"

# Central DB
export CENTRAL_DB_IMAGE_REPO="quay.io/rhacs-eng/central-db"
export CENTRAL_DB_IMAGE_TAG="$NIGHTLY_TAG"
export CENTRAL_DB_IMAGE="${CENTRAL_DB_IMAGE_REPO}:${CENTRAL_DB_IMAGE_TAG}"

# Scanner (V2)
export SCANNER_IMAGE_REPO="quay.io/rhacs-eng/scanner"
export SCANNER_IMAGE_TAG="$NIGHTLY_TAG"
export SCANNER_IMAGE="${SCANNER_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"

# Scanner DB (V2)
export SCANNER_DB_IMAGE_REPO="quay.io/rhacs-eng/scanner-db"
export SCANNER_DB_IMAGE="${SCANNER_DB_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"

# Scanner V4 (if enabled)
export SCANNER_V4_IMAGE_REPO="quay.io/rhacs-eng/scanner-v4"
export SCANNER_V4_IMAGE_TAG="$NIGHTLY_TAG"

# Scanner V4 DB (if enabled)
export SCANNER_V4_DB_IMAGE_REPO="quay.io/rhacs-eng/scanner-v4-db"
export SCANNER_V4_DB_IMAGE_TAG="$NIGHTLY_TAG"

# roxctl - use nightly version
export ROXCTL_IMAGE_REPO="quay.io/rhacs-eng/roxctl"
export ROXCTL_IMAGE_TAG="$NIGHTLY_TAG"
export ROXCTL_IMAGE="${ROXCTL_IMAGE_REPO}:${ROXCTL_IMAGE_TAG}"

# Use Docker-based roxctl
export USE_LOCAL_ROXCTL=true

# Display configuration
echo "Image Configuration:"
echo "  Main:         $MAIN_IMAGE"
echo "  Central-DB:   $CENTRAL_DB_IMAGE"
echo "  Scanner:      $SCANNER_IMAGE"
echo "  Scanner-DB:   $SCANNER_DB_IMAGE"
echo "  Scanner-V4:   ${SCANNER_V4_IMAGE_REPO}:${SCANNER_V4_IMAGE_TAG}"
echo "  Scanner-V4-DB: ${SCANNER_V4_DB_IMAGE_REPO}:${SCANNER_V4_DB_IMAGE_TAG}"
echo "  roxctl:       $ROXCTL_IMAGE"
echo ""

# Detect platform if not specified
if [[ -z "${PLATFORM:-}" ]]; then
    source "${SCRIPT_DIR}/deploy/detect.sh"
    if is_openshift; then
        PLATFORM="openshift"
    else
        PLATFORM="k8s"
    fi
fi

echo "Platform: $PLATFORM"
echo ""

# Additional deployment settings
export LOCAL_DEPLOYMENT="${LOCAL_DEPLOYMENT:-true}"
export COLLECTION_METHOD="${COLLECTION_METHOD:-core_bpf}"
export MONITORING_SUPPORT="${MONITORING_SUPPORT:-false}"
export POD_SECURITY_POLICIES="${POD_SECURITY_POLICIES:-false}"

# Use Helm for deployment
export OUTPUT_FORMAT="${OUTPUT_FORMAT:-helm}"

echo "Deployment Settings:"
echo "  Output format: $OUTPUT_FORMAT"
echo "  Local deployment: $LOCAL_DEPLOYMENT"
echo "  Collection method: $COLLECTION_METHOD"
echo "  Monitoring: $MONITORING_SUPPORT"
echo "  PSP: $POD_SECURITY_POLICIES"
echo ""

# Confirm before proceeding
read -p "Proceed with Central deployment? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 0
fi

echo ""
echo "Deploying Central only..."
echo ""

# Run central deployment
cd "${SCRIPT_DIR}/deploy/${PLATFORM}"
exec ./central.sh
