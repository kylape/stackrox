# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the StackRox Tekton pipelines.

## Architecture Overview

This repository contains Tekton pipelines for building StackRox components including:
- StackRox main components (Central, Sensor, etc.)
- Collector (runtime data gathering agent)
- Builder images for compilation

## Multi-Architecture Build Requirements

**IMPORTANT**: All container images MUST be built for multi-architecture support:
- `linux/arm64` (primary target)
- `linux/amd64` (secondary target)

This is implemented using buildah with:
1. Individual platform builds (`-arm64`, `-amd64` tagged images)
2. Manifest lists combining both architectures
3. Final multi-arch image push

## Collector Integration

The collector component requires special handling:

### Build Process
1. **Builder Image**: Collector requires a custom builder image (`collector-builder`) with C++ compilation tools
2. **Binary Build**: Collector is built as a native binary (not a Go binary like other components)
3. **Integration**: The collector binary is copied to the main `bin/` directory and included in the combined StackRox image
4. **Testing**: Unit tests are run as part of the build process

### Pipeline Structure
- **Builder Pipeline** (`pipeline-builder.yaml`): Builds both StackRox and collector builder images
- **Main Pipeline** (`pipeline-stackrox.yaml`): Uses builder images to compile all components including collector

### Key Tasks
- `collector-builder`: Builds the collector builder image for multi-arch
- `collector-build`: Compiles collector binary and runs unit tests
- `stackrox-builder`: Builds the StackRox builder image for multi-arch using base.Dockerfile (amd64) and base-arm.Dockerfile (arm64)

### Dependencies
- Collector build requires submodule initialization (`git submodule update --init --recursive collector`)
- Final image build must run after collector build to include the binary
- Collector builder image must be available before collector compilation

## Pipeline Execution

### Builder Images (Run First)
```bash
kubectl apply -f resources/stackrox/pipeline-builder.yaml
kubectl apply -f resources/stackrox/task-stackrox-builder.yaml
kubectl apply -f resources/stackrox/task-collector-builder.yaml
kubectl create -f resources/stackrox/pipelinerun-builder.yaml
```

### Main Build (Run After Builders)
```bash
kubectl apply -f resources/stackrox/pipeline-stackrox.yaml
kubectl apply -f resources/stackrox/task-collector-build.yaml
kubectl create -f resources/stackrox/pipelinerun-stackrox.yaml
```

## Container Registry

Default registry: `kind-registry:5000`
- Uses `--tls-verify=false` for local development
- Multi-arch images are pushed as manifest lists
- Individual architecture images are tagged with `-arm64` and `-amd64` suffixes

## Workspace Management

Pipelines use temporary PVCs via `volumeClaimTemplate`:
- Storage: 10Gi (adjustable based on build requirements)
- Access Mode: ReadWriteOnce
- Automatically cleaned up when PipelineRun completes