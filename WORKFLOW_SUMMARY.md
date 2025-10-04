# Complete Workflow: Custom Main Image with Nightly Builds

## TL;DR - Quick Commands

```bash
# Initial deployment (requires roxctl once)
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Daily development: update image only (no roxctl)
./update-main-image.sh abc124
./update-main-image.sh abc125
# ... iterate quickly ...

# Update nightly components (requires roxctl)
export HELM_REUSE_VALUES=true
./deploy-custom-central.sh abc125 4.6.x-nightly-20241010
```

## Complete Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Development Setup                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  localhost:5000/stackrox/main:abc123                        │
│  └─ Your custom code changes                                │
│                                                              │
│  quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003       │
│  quay.io/rhacs-eng/scanner:4.6.x-nightly-20241003          │
│  quay.io/rhacs-eng/scanner-db:4.6.x-nightly-20241003       │
│  quay.io/rhacs-eng/scanner-v4:4.6.x-nightly-20241003       │
│  quay.io/rhacs-eng/scanner-v4-db:4.6.x-nightly-20241003    │
│  └─ Production-quality components                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘

                            ↓

┌─────────────────────────────────────────────────────────────┐
│                   Deployment Process                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Step 1: roxctl generates Helm chart (if needed)            │
│  └─ Uses: quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003  │
│  └─ Generates chart matching nightly API versions           │
│                                                              │
│  Step 2: Helm deploys to Kubernetes                         │
│  └─ helm upgrade --install stackrox-central-services        │
│  └─ Rolling update strategy                                 │
│                                                              │
│  Step 3: Kubernetes pulls images                            │
│  └─ localhost:5000 → custom main                            │
│  └─ quay.io/rhacs-eng → other components                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘

                            ↓

┌─────────────────────────────────────────────────────────────┐
│                 Running in Kubernetes                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Pod: central (your custom code)                            │
│  Pod: central-db (nightly)                                  │
│  Pod: scanner (nightly)                                     │
│  Pod: scanner-db (nightly)                                  │
│  Pod: scanner-v4-indexer (nightly)                          │
│  Pod: scanner-v4-matcher (nightly)                          │
│  Pod: scanner-v4-db (nightly)                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Tool Usage by Operation

### Initial Deployment

**What runs**: `./deploy-custom-main.sh abc123 4.6.x-nightly-20241003`

```
Tools Used:
├─ roxctl (via Docker)
│  └─ Generates Helm chart from nightly roxctl image
│  └─ Time: ~10-30 seconds
│
├─ Helm
│  └─ Deploys chart to Kubernetes
│  └─ Time: ~2-5 minutes
│
└─ kubectl
   └─ Creates namespace, secrets
   └─ Time: ~5-10 seconds
```

**roxctl is required** because:
* Helm chart must match nightly API versions
* Chart includes version-specific CRDs
* No pre-built chart for nightly combinations

### Image Update (Fast Iteration)

**What runs**: `./update-main-image.sh abc124`

```
Tools Used:
└─ kubectl only
   └─ kubectl set image deployment/central central=...
   └─ Rolling update, zero downtime
   └─ Time: ~30-60 seconds
```

**No roxctl, no Helm, no chart regeneration**
* Fastest update method
* Perfect for development iterations
* Instant rollback available

### Component Version Update

**What runs**: `HELM_REUSE_VALUES=true ./deploy-custom-central.sh abc124 4.6.x-nightly-20241010`

```
Tools Used:
├─ roxctl (via Docker)
│  └─ Generates new chart for updated nightly version
│  └─ Time: ~10-30 seconds
│
└─ Helm
   └─ Updates deployment with new chart
   └─ Reuses existing values (preserves certs/secrets)
   └─ Time: ~1-3 minutes
```

**roxctl is required** because:
* New nightly version may have API changes
* Chart templates must match component versions

## roxctl Configuration Explained

In your scripts, you have `USE_LOCAL_ROXCTL=true`:

```bash
# deploy-custom-central.sh line 98
export USE_LOCAL_ROXCTL=true
```

**What this means**:

```bash
if USE_LOCAL_ROXCTL=true; then
  if local_roxctl_version == NIGHTLY_TAG; then
    # Use local roxctl (fast: ~1-5 seconds)
    roxctl central generate ...
  else
    # Version mismatch - fall back to Docker (slow: ~10-30 seconds)
    docker run quay.io/rhacs-eng/roxctl:$NIGHTLY_TAG central generate ...
  fi
fi
```

**Recommendation**:
* If you have local roxctl matching nightly version: Keep `USE_LOCAL_ROXCTL=true` (faster)
* If you don't: Set to `false` to always use Docker-based roxctl (guaranteed version match)

**Check your setup**:
```bash
# Check local roxctl version
roxctl version

# If it shows 4.6.x-nightly-20241003 and that's what you're deploying:
# → USE_LOCAL_ROXCTL=true will use local (fast)

# If it shows a different version:
# → USE_LOCAL_ROXCTL=true will fall back to Docker (slow)
# → Better to set USE_LOCAL_ROXCTL=false
```

## Complete Development Workflow Example

### Day 1: Initial Setup

```bash
# Build your custom image
cd ~/stackrox
make image
docker tag stackrox/main:$(make tag) localhost:5000/stackrox/main:abc123
docker push localhost:5000/stackrox/main:abc123

# Deploy with nightly components (requires roxctl)
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# Time: ~3-5 minutes
# roxctl: ~30 seconds
# Helm deploy: ~3 minutes
# Health checks: ~1 minute
```

### Day 2-7: Code Iterations

```bash
# Make code changes
vim pkg/central/something.go

# Build and push
make image
docker tag stackrox/main:$(make tag) localhost:5000/stackrox/main:abc124
docker push localhost:5000/stackrox/main:abc124

# Update deployment (NO roxctl)
./update-main-image.sh abc124

# Time: ~30-60 seconds
# kubectl update: ~10 seconds
# Rolling update: ~30 seconds
# Health check: ~10 seconds

# Repeat as needed
# ... abc125, abc126, abc127 ...
```

### Week 2: Update Nightly Components

```bash
# New nightly build available
NIGHTLY_NEW="4.6.x-nightly-20241010"

# Update components while preserving config (requires roxctl)
export HELM_REUSE_VALUES=true
./deploy-custom-central.sh abc127 $NIGHTLY_NEW

# Time: ~2-4 minutes
# roxctl: ~30 seconds (new chart for new nightly)
# Helm upgrade: ~2 minutes
# Health checks: ~1 minute

# Continue iterations with new nightly
./update-main-image.sh abc128
```

## Performance Comparison

| Operation | roxctl | Helm | kubectl | Total Time | Downtime |
|-----------|--------|------|---------|------------|----------|
| Initial deployment | ✅ 30s | ✅ 180s | ✅ 10s | ~220s | None |
| Image update (`update-main-image.sh`) | ❌ | ❌ | ✅ 30s | ~30s | None |
| Version update (Helm reuse) | ✅ 30s | ✅ 120s | ✅ 10s | ~160s | None |
| Full redeploy | ✅ 30s | ✅ 180s | ✅ 10s | ~220s | Brief |

## Minimizing roxctl Usage - Strategy

```bash
#!/usr/bin/env bash
# smart-deploy.sh - Minimize roxctl usage

CUSTOM_TAG="$1"
NIGHTLY_TAG="$2"
CURRENT_NIGHTLY="${3:-unknown}"

# Check what's currently deployed
if helm list -n stackrox | grep stackrox-central-services; then
  # Deployment exists

  # Check if nightly version changed
  if [[ "$NIGHTLY_TAG" == "$CURRENT_NIGHTLY" ]]; then
    echo "Nightly version unchanged - fast image update (no roxctl)"
    ./update-main-image.sh "$CUSTOM_TAG"
  else
    echo "Nightly version changed - Helm update (requires roxctl)"
    export HELM_REUSE_VALUES=true
    ./deploy-custom-central.sh "$CUSTOM_TAG" "$NIGHTLY_TAG"
  fi
else
  # No deployment - initial deploy (requires roxctl)
  echo "Initial deployment (requires roxctl)"
  ./deploy-custom-main.sh "$CUSTOM_TAG" "$NIGHTLY_TAG"
fi
```

## When Each Tool Runs

### roxctl Runs When:
* ✅ Initial Central deployment
* ✅ Updating nightly component versions
* ✅ Changing Central configuration requiring new chart
* ❌ Image-only updates
* ❌ Sensor deployment (uses Central API)
* ❌ Helm value-only updates

### Helm Runs When:
* ✅ Initial deployment
* ✅ Configuration updates
* ✅ Component version updates
* ❌ Image-only updates (kubectl is faster)

### kubectl Runs When:
* ✅ All deployments (namespace, secrets)
* ✅ Image-only updates (fastest method)
* ✅ Manual troubleshooting

## Troubleshooting Tools

```bash
# Check what's using what
ps aux | grep roxctl    # Is roxctl running?
ps aux | grep helm      # Is Helm running?

# Check roxctl version compatibility
roxctl version
docker run quay.io/rhacs-eng/roxctl:4.6.x-nightly-20241003 version

# Check Helm deployment
helm list -n stackrox
helm get values stackrox-central-services -n stackrox
helm history stackrox-central-services -n stackrox

# Check actual running images
kubectl get pods -n stackrox -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.containers[*]}{"\t"}{.image}{"\n"}{end}{end}'

# Verify update method worked
kubectl rollout status deployment/central -n stackrox
```

## Recommended Setup

```bash
# ~/.bashrc or ~/.zshrc
export REGISTRY_USERNAME="your-quay-username"
export REGISTRY_PASSWORD="your-quay-password"

# Aliases for quick access
alias deploy-stack='cd ~/stackrox && ./deploy-custom-main.sh'
alias update-stack='cd ~/stackrox && ./update-main-image.sh'
alias rollback-stack='helm rollback stackrox-central-services -n stackrox'

# Quick deployment function
function quick-deploy() {
  local tag="${1:-$(git rev-parse --short HEAD)}"
  make image
  docker tag stackrox/main:$(make tag) localhost:5000/stackrox/main:$tag
  docker push localhost:5000/stackrox/main:$tag
  update-stack $tag
}

# Usage:
# quick-deploy        # Uses git commit SHA
# quick-deploy abc123 # Uses custom tag
```

## Summary

Your setup with `USE_LOCAL_ROXCTL=true` is **optimal if your local roxctl matches the nightly version**. Otherwise, consider `USE_LOCAL_ROXCTL=false` for guaranteed version matching.

**For 99% of your work**: Use `update-main-image.sh` to avoid roxctl entirely after initial deployment.

**roxctl is only needed** when:
1. Initial Central deployment
2. Updating nightly component versions

**Everything else** (daily development, testing, iterations) can use roxctl-free updates.
