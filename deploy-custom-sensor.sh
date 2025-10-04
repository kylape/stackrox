#!/usr/bin/env bash
set -euo pipefail

# Deploy only StackRox Sensor with custom main image
#
# Usage:
#   ./deploy-custom-sensor.sh [CUSTOM_MAIN_TAG] [CLUSTER_NAME]
#
# Example:
#   ./deploy-custom-sensor.sh abc123 my-test-cluster

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
CUSTOM_MAIN_TAG="${1:-}"
CLUSTER_NAME="${2:-}"

if [[ -z "$CUSTOM_MAIN_TAG" ]]; then
    echo "Error: Custom main image tag required"
    echo "Usage: $0 CUSTOM_MAIN_TAG [CLUSTER_NAME]"
    echo "Example: $0 abc123 my-test-cluster"
    exit 1
fi

if [[ -z "$CLUSTER_NAME" ]]; then
    echo "Error: Cluster name required"
    echo "Usage: $0 CUSTOM_MAIN_TAG CLUSTER_NAME"
    echo "Example: $0 abc123 my-test-cluster"
    exit 1
fi

echo "============================================="
echo "Custom StackRox Sensor Deployment"
echo "============================================="
echo ""
echo "Custom main image tag: $CUSTOM_MAIN_TAG"
echo "Cluster name: $CLUSTER_NAME"
echo ""

# Prompt for registry credentials if needed (for collector/admission controller images)
if [[ -z "${REGISTRY_USERNAME:-}" ]]; then
    read -p "Quay.io username (or press Enter to skip): " REGISTRY_USERNAME
    export REGISTRY_USERNAME
fi

if [[ -n "$REGISTRY_USERNAME" && -z "${REGISTRY_PASSWORD:-}" ]]; then
    read -sp "Quay.io password: " REGISTRY_PASSWORD
    echo ""
    export REGISTRY_PASSWORD
fi

# Configure main image (sensor, collector, admission controller use main image)
export MAIN_IMAGE_REPO="localhost:5000/stackrox/main"
export MAIN_IMAGE_TAG="$CUSTOM_MAIN_TAG"
export MAIN_IMAGE="${MAIN_IMAGE_REPO}:${MAIN_IMAGE_TAG}"

echo ""
echo "Image Configuration:"
echo "  Main (Sensor/Collector/Admission-Controller): $MAIN_IMAGE"
echo ""

# Set cluster name
export CLUSTER="$CLUSTER_NAME"

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
export SENSOR_DEV_RESOURCES="${SENSOR_DEV_RESOURCES:-true}"

# Use Helm for deployment (auto-detected if Helm v3 available)
export SENSOR_HELM_DEPLOY="${SENSOR_HELM_DEPLOY:-true}"

echo "Deployment Settings:"
echo "  Cluster: $CLUSTER"
echo "  Helm deployment: $SENSOR_HELM_DEPLOY"
echo "  Local deployment: $LOCAL_DEPLOYMENT"
echo "  Collection method: $COLLECTION_METHOD"
echo "  Dev resources: $SENSOR_DEV_RESOURCES"
echo ""

# Check for admin password
PASSWORD_FILE="${SCRIPT_DIR}/deploy/${PLATFORM}/central-deploy/password"
if [[ -f "$PASSWORD_FILE" ]]; then
    export ROX_ADMIN_PASSWORD="$(cat "$PASSWORD_FILE")"
    echo "Using admin password from: $PASSWORD_FILE"
else
    if [[ -z "${ROX_ADMIN_PASSWORD:-}" ]]; then
        read -sp "Central admin password: " ROX_ADMIN_PASSWORD
        echo ""
        export ROX_ADMIN_PASSWORD
    fi
fi

echo ""

# Confirm before proceeding
read -p "Proceed with Sensor deployment? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 0
fi

echo ""
echo "Deploying Sensor only..."
echo ""

# Run sensor deployment
cd "${SCRIPT_DIR}/deploy/${PLATFORM}"
exec ./sensor.sh
