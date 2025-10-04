#!/usr/bin/env bash
set -euo pipefail

# Update main image on running StackRox deployment with zero downtime
#
# This script performs a rolling update of the main image without
# regenerating secrets, certificates, or other configuration.
#
# Usage:
#   ./update-main-image.sh [NEW_IMAGE_TAG] [NAMESPACE]
#
# Example:
#   ./update-main-image.sh xyz789 stackrox

NEW_TAG="${1:-}"
NAMESPACE="${2:-stackrox}"

if [[ -z "$NEW_TAG" ]]; then
    echo "Error: New image tag required"
    echo "Usage: $0 NEW_IMAGE_TAG [NAMESPACE]"
    echo "Example: $0 xyz789 stackrox"
    exit 1
fi

NEW_IMAGE="localhost:5000/stackrox/main:${NEW_TAG}"

echo "============================================="
echo "StackRox Rolling Image Update"
echo "============================================="
echo ""
echo "Namespace: $NAMESPACE"
echo "New main image: $NEW_IMAGE"
echo ""

# Check if deployments exist
if ! kubectl get deployment central -n "$NAMESPACE" &>/dev/null; then
    echo "Error: Central deployment not found in namespace $NAMESPACE"
    exit 1
fi

# Show current images
echo "Current images:"
kubectl get deployment central -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[?(@.name=="central")].image}'
echo ""
echo ""

# Confirm
read -p "Proceed with rolling update? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Update cancelled"
    exit 0
fi

echo ""
echo "Updating Central deployment..."
kubectl set image deployment/central \
    central="$NEW_IMAGE" \
    -n "$NAMESPACE"

echo ""
echo "Waiting for rollout to complete..."
kubectl rollout status deployment/central -n "$NAMESPACE" --timeout=10m

echo ""
echo "✓ Central updated successfully"
echo ""

# Update Sensor if it exists
if kubectl get deployment sensor -n "$NAMESPACE" &>/dev/null; then
    echo "Found Sensor deployment, updating..."

    kubectl set image deployment/sensor \
        sensor="$NEW_IMAGE" \
        -n "$NAMESPACE"

    kubectl rollout status deployment/sensor -n "$NAMESPACE" --timeout=10m
    echo "✓ Sensor updated successfully"
    echo ""
fi

# Update Admission Controller if it exists
if kubectl get deployment admission-control -n "$NAMESPACE" &>/dev/null; then
    echo "Found Admission Controller deployment, updating..."

    kubectl set image deployment/admission-control \
        admission-control="$NEW_IMAGE" \
        -n "$NAMESPACE"

    kubectl rollout status deployment/admission-control -n "$NAMESPACE" --timeout=10m
    echo "✓ Admission Controller updated successfully"
    echo ""
fi

# Update Collector DaemonSet if it exists
if kubectl get daemonset collector -n "$NAMESPACE" &>/dev/null; then
    echo "Found Collector daemonset, updating..."

    kubectl set image daemonset/collector \
        collector="$NEW_IMAGE" \
        -n "$NAMESPACE"

    kubectl rollout status daemonset/collector -n "$NAMESPACE" --timeout=10m
    echo "✓ Collector updated successfully"
    echo ""
fi

echo ""
echo "============================================="
echo "Update Complete!"
echo "============================================="
echo ""
echo "Verify deployment:"
echo "  kubectl get pods -n $NAMESPACE"
echo "  kubectl get deployment -n $NAMESPACE -o wide"
echo ""
echo "Check logs:"
echo "  kubectl logs -n $NAMESPACE deployment/central -c central --tail=50"
echo ""
echo "Rollback if needed:"
echo "  kubectl rollout undo deployment/central -n $NAMESPACE"
echo "  kubectl rollout undo deployment/sensor -n $NAMESPACE"
echo ""
