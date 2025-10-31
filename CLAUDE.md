# Inner Loop Development Session: image-build

This is an isolated inner loop development environment for rapid prototyping and development.

## Session Information

* **Session Name**: image-build
* **Cluster Name**: stackrox-image-build
* **Worktree**: /root/workspace/worktrees/image-build
* **Session Directory**: /root/workspace/sessions/image-build
* **Kubeconfig**: /root/workspace/sessions/image-build/kubeconfig

## IMPORTANT: Kubernetes Context

This tmux window has KUBECONFIG set to this session's cluster.
Each tmux window can have its own KUBECONFIG pointing to different clusters.

* **Current KUBECONFIG**: /root/workspace/sessions/image-build/kubeconfig
* **Current context**: kind-stackrox-image-build

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

Build StackRox components rapidly:

```bash
# Build using session helper (recommended)
/root/workspace/sessions/image-build/build.sh

# Or build manually in worktree
cd /root/workspace/worktrees/image-build
# Add build commands here
```

### Deploy Commands

Deploy to the session's KinD cluster using roxie:

```bash
# Deploy using helper script (recommended)
/root/workspace/sessions/image-build/deploy.sh

# Or use roxie directly
cd /root/workspace/src/roxie
export KUBECONFIG=/root/workspace/sessions/image-build/kubeconfig
./bin/roxie deploy both

# Deploy just central
./bin/roxie deploy central

# Deploy just secured-cluster
./bin/roxie deploy secured-cluster

# Check deployment status
kubectl get pods -n stackrox
```

### Validation Commands

Verify deployment and functionality:

```bash
# Run validation checks
/root/workspace/sessions/image-build/validate.sh

# Manual checks
export KUBECONFIG=/root/workspace/sessions/image-build/kubeconfig
kubectl get pods -n stackrox
kubectl get deployments -n stackrox

# Test StackRox API
BASIC_AUTH="Basic $(echo -n 'admin:letmein' | base64)"
kubectl run -n stackrox curl-test --rm -i --tty --image=curlimages/curl -- \
  curl -k -H "Authorization: $BASIC_AUTH" https://central.stackrox.svc:443/v1/ping
```

### Development Workflow

1. **Make changes** in the worktree at /root/workspace/worktrees/image-build
2. **Build** using `/root/workspace/sessions/image-build/build.sh`
3. **Deploy** using `/root/workspace/sessions/image-build/deploy.sh`
4. **Validate** using `/root/workspace/sessions/image-build/validate.sh`
5. **Iterate** quickly without affecting other development

### Important Notes

* This is an ISOLATED environment - changes here don't affect the main workspace
* The KinD cluster is ephemeral - it can be recreated anytime
* Remember to push your worktree changes back to the main repo when done
* Use `kind delete cluster --name stackrox-image-build` to clean up the cluster

### Cleanup

When done with this session:

```bash
# Use the teardown script (recommended - handles everything safely)
/root/workspace/hack/teardown-session.sh image-build

# Or teardown current session (auto-detected)
/root/workspace/hack/teardown-session.sh

# Manual cleanup (if needed):
# 1. Delete the KinD cluster
kind delete cluster --name stackrox-image-build

# 2. Remove the worktree (after committing/pushing changes!)
cd /root/workspace/src/stackrox
git worktree remove /root/workspace/worktrees/image-build

# 3. Optional: Remove session directory
rm -rf /root/workspace/sessions/image-build
```

## Helper Scripts Location

All helper scripts are in: /root/workspace/sessions/image-build/

* `build.sh` - Build StackRox components
* `deploy.sh` - Deploy to KinD cluster
* `validate.sh` - Validate deployment
* `env.sh` - Environment setup (source this in your shell)

