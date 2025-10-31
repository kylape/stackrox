# Fast Inner Loop Development for StackRox

This document describes the fast build workflow for rapid iteration during StackRox development.

## Overview

The fast build workflow significantly speeds up the inner loop by:

1. Using a pre-built base image from `quay.io/rhacs-eng/main` instead of building from scratch
2. Only building and copying the Go binaries you're actively developing
3. Skipping UI builds, RPM downloads, and other time-consuming steps

**Traditional build time**: 15-30 minutes
**Fast build time**: 2-5 minutes

## Quick Start

### Using Session Helper Scripts (Recommended)

The session includes helper scripts that automate the entire workflow:

```bash
# Build binaries, create image, and load into kind cluster
/root/workspace/sessions/image-build/build.sh

# Deploy to the cluster using roxie
/root/workspace/sessions/image-build/deploy.sh

# Validate the deployment
/root/workspace/sessions/image-build/validate.sh
```

### Using Make Targets Directly

```bash
cd /root/workspace/worktrees/image-build

# Build just the binaries
make fast-binaries

# Build binaries and create Docker image
make fast-image

# Build, create image, and load into kind cluster
make fast-load-kind

# Complete inner loop (recommended)
make fast-inner-loop
```

## Customization

### Using a Different Base Image Tag

By default, the workflow uses `quay.io/rhacs-eng/main:4.6.x-latest`. You can customize this:

```bash
# Using environment variable
BASE_TAG=4.5.x-latest /root/workspace/sessions/image-build/build.sh

# Using make parameter
make fast-inner-loop BASE_TAG=4.5.x-latest
```

### Using a Different Image Tag

By default, the built image is tagged as `stackrox/main:local-dev`. You can customize this:

```bash
# Using environment variable
IMAGE_TAG=my-feature /root/workspace/sessions/image-build/build.sh

# Using make parameter
make fast-inner-loop IMAGE_TAG=my-feature
```

### Using a Different Cluster

If you're not using the default `stackrox-image-build` cluster:

```bash
make fast-inner-loop CLUSTER_NAME=my-cluster
```

## What Gets Built

The fast build creates these binaries using `go-build.sh`:

* `central` - Main central service
* `migrator` - Database migration tool
* `compliance` - Compliance checking service
* `kubernetes-sensor` - Kubernetes sensor for monitoring
* `sensor-upgrader` - Sensor upgrade utility
* `admission-control` - Admission control webhook
* `config-controller` - Configuration management controller
* `init-tls-certs` - TLS certificate initialization

All binaries are built with the same flags as the full build using `scripts/go-build.sh`.

## Files Created

* `Dockerfile.fastbuild` - Dockerfile that layers local binaries over the base image
* `Makefile` - Added fast build targets at the end:
  * `fast-binaries` - Build Go binaries only
  * `fast-image` - Build Docker image with local binaries
  * `fast-load-kind` - Load image into kind cluster
  * `fast-inner-loop` - Complete workflow

## How It Works

### Step 1: Build Binaries

```bash
make fast-binaries
```

This runs `go-build.sh` to compile the Go binaries with the correct flags:
* Builds with proper ldflags from `status.sh`
* Supports `DEBUG_BUILD=yes` for debugging
* Uses `GOTAGS` for conditional compilation
* Outputs to `bin/linux_amd64/` directory

### Step 2: Create Docker Image

```bash
make fast-image
```

This uses `Dockerfile.fastbuild` to:
1. Pull the base image from `quay.io/rhacs-eng/main:${BASE_TAG}`
2. Copy locally-built binaries over the ones in the base image
3. Set correct ownership (UID 4000)
4. Tag as `stackrox/main:${IMAGE_TAG}`

### Step 3: Load into Kind

```bash
make fast-load-kind
```

This loads the image directly into the kind cluster's container registry.

## Debugging

### Enable Debug Build

To build with debug symbols and disable optimizations:

```bash
DEBUG_BUILD=yes make fast-inner-loop
```

### Enable Race Detection

To build with Go's race detector:

```bash
RACE=true make fast-binaries
```

Note: Race detection requires `CGO_ENABLED=1` and will slow down the build.

### Check Build Flags

The `go-build.sh` script automatically sets build flags based on `status.sh`. To see what flags are being used, check the build output.

## Troubleshooting

### Base image pull fails

If you can't pull from `quay.io/rhacs-eng`, ensure you're authenticated:

```bash
docker login quay.io
```

### Binaries not found

Ensure you run `make fast-binaries` or `make fast-image` before trying to build the Docker image directly. The Makefile dependencies handle this automatically.

### Kind load fails

Check that your kind cluster is running:

```bash
kind get clusters
```

Ensure the cluster name matches (default: `stackrox-image-build`).

### Deployment fails with image pull errors

When deploying with roxie, ensure you set the image pull policy to `Never`:

```bash
./bin/roxie deploy both \
    --main-image "stackrox/main:local-dev" \
    --image-pull-policy Never
```

The helper script `deploy.sh` does this automatically.

## Complete Workflow Example

```bash
# 1. Make your code changes
vim central/somefeature/feature.go

# 2. Build and load into cluster
/root/workspace/sessions/image-build/build.sh

# 3. Deploy (or redeploy) to cluster
/root/workspace/sessions/image-build/deploy.sh

# 4. Test your changes
kubectl logs -n stackrox deploy/central -f

# 5. Iterate - repeat steps 1-4
```

## Integration with roxie

The deploy script uses roxie with these key parameters:

* `--main-image stackrox/main:local-dev` - Use the locally-built image
* `--image-pull-policy Never` - Don't pull from registry, use local image

Roxie handles:
* Creating the stackrox namespace
* Deploying central
* Deploying secured-cluster components
* Configuring networking and RBAC

## Performance Comparison

| Build Type | Time | What It Builds |
|------------|------|----------------|
| Full build (`make image`) | 15-30 min | Everything: UI, binaries, RPMs, base images |
| Fast build (`make fast-inner-loop`) | 2-5 min | Just the Go binaries |

## When to Use Full Build

Use the full build when:

* You're changing UI code
* You're changing the base image or Dockerfile
* You're adding new RPM dependencies
* You're preparing for a release or PR
* You need to test the exact production image

## When to Use Fast Build

Use the fast build when:

* You're iterating on Go code in central or sensor components
* You want rapid feedback during development
* You're debugging or testing specific features
* You're doing inner loop development

## Additional Resources

* [StackRox Build System](./README.md)
* [Development Environment Setup](../CLAUDE.md)
* [Inner Loop Session Guide](./CLAUDE.md)
