# Fork Container Image Building Setup

This document explains how to set up container image building on your StackRox fork using GitHub Actions.

## Overview

The `.github/workflows/fork-build.yaml` workflow provides a simplified version of the main StackRox build pipeline optimized for fork development. It builds:

- **Main StackRox image**: Multi-architecture (amd64/arm64) container with all components
- **roxctl CLI image**: Command-line tool container
- Both **GitHub Container Registry (GHCR)** and **Docker Hub** support

## Quick Setup

### 1. Enable GitHub Actions (if not already enabled)
- Go to your fork: `https://github.com/kylape/stackrox`
- Navigate to **Settings** → **Actions** → **General**
- Ensure "Allow all actions and reusable workflows" is selected

### 2. Enable GitHub Container Registry
- Go to **Settings** → **Actions** → **General**
- Under "Workflow permissions", select "Read and write permissions"
- Check "Allow GitHub Actions to create and approve pull requests"

### 3. Trigger a Build

**Option A: Manual Trigger**
- Go to **Actions** tab in your fork
- Select "Fork Build" workflow
- Click "Run workflow"
- Choose options:
  - `build_images`: true/false (build container images)
  - `registry`: ghcr.io or docker.io

**Option B: Automatic Trigger**
- Push to branches: `scanner-v4-ci-with-installer`, `feature/*`, `dev/*`
- Images will be built automatically

## Registry Options

### GitHub Container Registry (GHCR) - Recommended
- **Registry**: `ghcr.io`
- **Authentication**: Uses `GITHUB_TOKEN` (automatic)
- **Images**: `ghcr.io/kylape/stackrox:latest`
- **Benefits**: No additional setup, unlimited private repositories

### Docker Hub
- **Registry**: `docker.io`
- **Setup Required**:
  1. Create Docker Hub account if needed
  2. Go to **Settings** → **Secrets and variables** → **Actions**
  3. Add secrets:
     - `DOCKERHUB_USERNAME`: Your Docker Hub username
     - `DOCKERHUB_TOKEN`: Docker Hub access token
- **Images**: `docker.io/kylape/stackrox:latest`

## Built Images

After a successful build, you'll have:

```bash
# Main StackRox image (multi-arch)
ghcr.io/kylape/stackrox:scanner-v4-ci-with-installer
ghcr.io/kylape/stackrox:scanner-v4-ci-with-installer-abc1234  # SHA tag

# roxctl CLI image (multi-arch)  
ghcr.io/kylape/stackrox/roxctl:abc1234
```

## Using Built Images

### Local Development
```bash
# Pull and use your built image
docker pull ghcr.io/kylape/stackrox:latest
docker run -it ghcr.io/kylape/stackrox:latest

# Use with your installer
echo "image: ghcr.io/kylape/stackrox:scanner-v4-ci-with-installer" >> installer.yaml
./bin/installer apply central
```

### Testing with roxctl
```bash
# Pull your custom roxctl
docker pull ghcr.io/kylape/stackrox/roxctl:abc1234
docker run --rm ghcr.io/kylape/stackrox/roxctl:abc1234 version
```

## Workflow Details

### Build Process
1. **UI Build**: Compiles React frontend
2. **CLI Build**: Builds roxctl and other CLI tools  
3. **Go Binaries**: Compiles all Go services (amd64/arm64)
4. **Documentation**: Generates API docs
5. **Container Build**: Creates multi-arch images
6. **Registry Push**: Uploads to chosen registry

### Differences from Main Workflow
- **Simplified**: Removes enterprise-specific steps
- **Fork-friendly**: Uses GitHub tokens instead of Quay secrets
- **Development-focused**: Builds only essential images
- **Multi-arch**: Supports amd64 and arm64 (no s390x/ppc64le)

## Troubleshooting

### Permission Errors
- Ensure "Read and write permissions" is enabled in Actions settings
- Check that GITHUB_TOKEN has package write permissions

### Build Failures
- Check the Actions tab for detailed logs
- Common issues:
  - Missing UI dependencies (usually self-resolving)
  - Docker layer caching issues (retry the workflow)
  - Architecture-specific build problems

### Registry Issues
- **GHCR**: Should work automatically with proper permissions
- **Docker Hub**: Verify username/token secrets are correct

## Advanced Usage

### Custom Branch Patterns
Edit `.github/workflows/fork-build.yaml` to add your branch patterns:
```yaml
push:
  branches:
    - 'scanner-v4-ci-with-installer'
    - 'feature/*' 
    - 'dev/*'
    - 'your-custom-pattern'  # Add this
```

### Custom Image Tags
The workflow automatically creates tags based on:
- Branch name: `scanner-v4-ci-with-installer`
- Git SHA: `scanner-v4-ci-with-installer-abc1234`
- Latest: `latest` (for default branch)

### Integration with test-installer.sh
Update your installer config to use your fork's images:
```bash
# In installer.yaml
cat >> installer.yaml << EOF
image: ghcr.io/kylape/stackrox:scanner-v4-ci-with-installer
EOF

./test-installer.sh
```

## Next Steps

1. **Push changes** to trigger your first build
2. **Monitor the Actions tab** for build progress  
3. **Pull and test** your built images locally
4. **Integrate with your development workflow** using the installer

Your fork now has the same container building capabilities as the main repository, optimized for development use!