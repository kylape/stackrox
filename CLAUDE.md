# Inner Loop Development Session: policy-as-code-v2

This is an isolated inner loop development environment for rapid prototyping and development.

## Session Information

* **Session Name**: policy-as-code-v2
* **Cluster Name**: stackrox-policy-as-code-v2
* **Worktree**: /root/workspace/worktrees/policy-as-code-v2
* **Session Directory**: /root/workspace/sessions/policy-as-code-v2
* **Kubeconfig**: /root/workspace/sessions/policy-as-code-v2/kubeconfig

## IMPORTANT: Kubernetes Context

This tmux window has KUBECONFIG set to this session's cluster.
Each tmux window can have its own KUBECONFIG pointing to different clusters.

* **Current KUBECONFIG**: /root/workspace/sessions/policy-as-code-v2/kubeconfig
* **Current context**: kind-stackrox-policy-as-code-v2

You can run multiple sessions in different tmux windows, each with its own cluster:
- Window 1: feature-a (cluster: stackrox-feature-a)
- Window 2: feature-b (cluster: stackrox-feature-b)

## Environment Setup

This session has:

* Dedicated KinD cluster with 1 control-plane node
* Git worktree isolated from main development
* Custom helper scripts for rapid iteration
* Window-specific KUBECONFIG for cluster isolation

## Quick Reference

### Build Commands

Build StackRox components using the fast build workflow (2-5 minutes):

```bash
# Build using session helper (recommended)
/root/workspace/sessions/policy-as-code-v2/build.sh

# Or build manually in worktree
cd /root/workspace/worktrees/policy-as-code-v2

# Fast build (builds binaries, creates image, loads into cluster)
make fast-inner-loop CLUSTER_NAME=stackrox-policy-as-code-v2

# Customize base image tag
BASE_TAG=4.6.x-latest make fast-inner-loop CLUSTER_NAME=stackrox-policy-as-code-v2

# Just build binaries (no image creation)
make fast-binaries

# Build and create image (don't load into cluster)
make fast-image IMAGE_TAG=local-dev
```

### Deploy Commands

Deploy to the session's KinD cluster using roxctl-generated helm charts:

```bash
# Deploy using helper script (recommended)
/root/workspace/sessions/policy-as-code-v2/deploy.sh

# Or deploy manually with roxctl + helm
cd /root/workspace/worktrees/policy-as-code-v2

# Ensure roxctl is built (builds only for current architecture)
./scripts/go-build.sh roxctl

# Generate helm chart
bin/$(go env GOOS)_$(go env GOARCH)/roxctl helm output central-services \
    --output-dir /root/workspace/sessions/policy-as-code-v2/helm-chart \
    --remove

# Deploy StackRox (unified chart includes Central + Scanner)
helm upgrade --install -n stackrox --create-namespace \
    stackrox-central-services /root/workspace/sessions/policy-as-code-v2/helm-chart \
    --set imagePullPolicy=IfNotPresent

# Check deployment status
kubectl get pods -n stackrox
```

### Admin Credentials

After deploying, admin credentials are saved to:

```
/root/workspace/sessions/policy-as-code-v2/admin-password.txt
```

**Default credentials:**
- Username: `admin`
- Password: See `admin-password.txt` (typically `letmein` for local dev)

**Using in tests:**

```bash
# Password is automatically loaded by test scripts
export ROX_ADMIN_PASSWORD=$(cat /root/workspace/sessions/policy-as-code-v2/admin-password.txt)
export API_ENDPOINT=central.stackrox.svc:443
go test -v -tags test_e2e ./tests
```

### Validation Commands

Verify deployment and functionality:

```bash
# Run validation checks
/root/workspace/sessions/policy-as-code-v2/validate.sh

# Manual checks
export KUBECONFIG=/root/workspace/sessions/policy-as-code-v2/kubeconfig
kubectl get pods -n stackrox
kubectl get deployments -n stackrox

# Test StackRox API
BASIC_AUTH="Basic $(echo -n 'admin:letmein' | base64)"
kubectl run -n stackrox curl-test --rm -i --tty --image=curlimages/curl -- \
  curl -k -H "Authorization: $BASIC_AUTH" https://central.stackrox.svc:443/v1/ping
```

### Development Workflow

After sourcing the environment (`source /root/workspace/sessions/policy-as-code-v2/env.sh`):

1. **Make changes** in the worktree at /root/workspace/worktrees/policy-as-code-v2
2. **Build** using `build` (or `/root/workspace/sessions/policy-as-code-v2/build.sh`)
3. **Deploy** using `deploy` (or `/root/workspace/sessions/policy-as-code-v2/deploy.sh`)
4. **Validate** using `validate` (or `/root/workspace/sessions/policy-as-code-v2/validate.sh`)
5. **Iterate** quickly without affecting other development

### Helper Commands

Once you source the environment file (`source /root/workspace/sessions/policy-as-code-v2/env.sh`), these commands are available:

**Build, Deploy, Validate:**
* `build` - Build StackRox components
* `deploy` - Deploy to KinD cluster
* `validate` - Validate deployment

**Kubectl shortcuts:**
* `k` - Alias for kubectl
* `kgs` - Get pods in stackrox namespace
* `kgp` - Get all pods
* `kl` - View logs in stackrox namespace
* `kdel` - Delete the cluster

### Important Notes

* This is an ISOLATED environment - changes here don't affect the main workspace
* The KinD cluster is ephemeral - it can be recreated anytime
* Remember to push your worktree changes back to the main repo when done
* Use `kind delete cluster --name stackrox-policy-as-code-v2` to clean up the cluster

### Cleanup

When done with this session:

```bash
# Use the teardown script (recommended - handles everything safely)
/root/workspace/hack/teardown-session.sh policy-as-code-v2

# Or teardown current session (auto-detected)
/root/workspace/hack/teardown-session.sh

# Manual cleanup (if needed):
# 1. Delete the KinD cluster
kind delete cluster --name stackrox-policy-as-code-v2

# 2. Remove the worktree (after committing/pushing changes!)
cd /root/workspace/src/stackrox
git worktree remove /root/workspace/worktrees/policy-as-code-v2

# 3. Optional: Remove session directory
rm -rf /root/workspace/sessions/policy-as-code-v2
```

## Helper Scripts Location

All helper scripts are in: /root/workspace/sessions/policy-as-code-v2/

* `build.sh` - Build StackRox components
* `deploy.sh` - Deploy to KinD cluster
* `validate.sh` - Validate deployment
* `env.sh` - Environment setup (source this in your shell)

