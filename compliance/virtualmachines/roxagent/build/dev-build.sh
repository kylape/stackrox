#!/bin/bash
# roxagent development build and deploy script
#
# Usage: ./dev-build.sh [--run]
#
# Builds roxagent, copies to the RHEL VM, builds container image, and optionally runs it.
# The VM must have the quadlet configured to use localhost/roxagent:dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACKROX_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VM_HOST="${VM_HOST:-localhost}"
VM_PORT="${VM_PORT:-2222}"
VM_USER="${VM_USER:-cloud-user}"
RUN_AFTER_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --run)
            RUN_AFTER_BUILD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--run]"
            exit 1
            ;;
    esac
done

echo "==> Building roxagent..."
cd "$STACKROX_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/roxagent ./compliance/virtualmachines/roxagent

echo "==> Copying binary and Dockerfile to VM..."
scp -o StrictHostKeyChecking=no -P "$VM_PORT" /tmp/roxagent "$VM_USER@$VM_HOST:/tmp/roxagent"
scp -o StrictHostKeyChecking=no -P "$VM_PORT" "$SCRIPT_DIR/Dockerfile" "$VM_USER@$VM_HOST:/tmp/Dockerfile"

echo "==> Building container image on VM..."
ssh -o StrictHostKeyChecking=no -p "$VM_PORT" "$VM_USER@$VM_HOST" \
    'cd /tmp && sudo podman build -t localhost/roxagent:dev -f Dockerfile .'

if [ "$RUN_AFTER_BUILD" = true ]; then
    echo "==> Running roxagent service..."
    ssh -o StrictHostKeyChecking=no -p "$VM_PORT" "$VM_USER@$VM_HOST" \
        'sudo systemctl start roxagent-prep.service && sudo systemctl start roxagent.service'

    echo "==> Waiting for completion..."
    sleep 3

    echo "==> Service logs:"
    ssh -o StrictHostKeyChecking=no -p "$VM_PORT" "$VM_USER@$VM_HOST" \
        'sudo journalctl -u roxagent.service --no-pager -n 10'
fi

echo ""
echo "==> Done!"
echo ""
echo "Dev workflow:"
echo "  1. Edit code in $STACKROX_DIR/compliance/virtualmachines/roxagent/"
echo "  2. Run: $SCRIPT_DIR/dev-build.sh --run"
echo "  3. Check StackRox API for updated scan results"
echo ""
echo "Manual commands:"
echo "  Run service:  ssh -p $VM_PORT $VM_USER@$VM_HOST 'sudo systemctl start roxagent.service'"
echo "  View logs:    ssh -p $VM_PORT $VM_USER@$VM_HOST 'sudo journalctl -u roxagent.service -f'"
echo "  Run verbose:  ssh -p $VM_PORT $VM_USER@$VM_HOST 'sudo podman run --rm --privileged ... localhost/roxagent:dev --verbose'"
