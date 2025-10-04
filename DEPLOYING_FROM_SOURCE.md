# Deploying from Source Code Helm Charts

## Overview

If you have the StackRox source code, you can use the Helm chart templates directly from `image/templates/helm/` instead of having roxctl generate them. This is **faster and gives you more control**.

## Source Code Chart Locations

```
stackrox/
└── image/
    └── templates/
        └── helm/
            ├── stackrox-central/          # Central services chart
            ├── stackrox-secured-cluster/  # Sensor services chart
            └── shared/                    # Shared templates
```

## How It Works

### Traditional Approach (roxctl central generate)

```bash
# What deploy-custom-main.sh does:
roxctl central generate kubernetes \
  --output-format helm \
  -i localhost:5001/stackrox/main:abc123 \
  --central-db-image quay.io/rhacs-eng/central-db:4.6.x-nightly-20241003
  # ... generates complete chart with all settings baked in
```

**Time**: ~30 seconds (pulls roxctl image, generates everything)

### Source-Based Approach (roxctl helm output)

```bash
# What deploy-from-source.sh does:
roxctl helm output central-services \
  --output-dir ./helm-output \
  --image-defaults=development_build
  # ... renders .htpl meta-templates to actual Helm chart

# Then customize via values:
helm upgrade --install stackrox-central-services \
  ./helm-output/stackrox-central-services-chart/ \
  --set image.tag=abc123 \
  --set central.db.image.tag=4.6.x-nightly-20241003
```

**Time**: ~5-10 seconds (just renders templates)

## Key Differences

| Aspect | roxctl central generate | roxctl helm output |
|--------|------------------------|-------------------|
| **Purpose** | Generate deployment bundle | Render chart templates |
| **Input** | All deployment settings | Template source code |
| **Output** | Complete chart with baked values | Generic chart template |
| **Customization** | Via roxctl flags | Via Helm values |
| **Speed** | Slower (~30s) | Faster (~5s) |
| **Flexibility** | Limited to roxctl flags | Full Helm values control |
| **Updates** | Regenerate each time | Reuse chart, update values |

## Using deploy-from-source.sh

### Initial Deployment

```bash
./deploy-from-source.sh abc123 4.6.x-nightly-20241003
```

This will:
1. Render Helm chart from source using `roxctl helm output` (~5 seconds)
2. Create custom values file with your image configuration
3. Deploy using standard Helm

**Chart is saved to**: `./helm-output/stackrox-central-services-chart/`

### Subsequent Updates

Since the chart is already rendered, you can update faster:

```bash
# Update main image only (no roxctl at all!)
helm upgrade stackrox-central-services \
  ./helm-output/stackrox-central-services-chart/ \
  --namespace stackrox \
  --reuse-values \
  --set image.tag=abc124
```

**Time**: ~10 seconds (Helm only, no roxctl)

Or use the image update script:
```bash
./update-main-image.sh abc124
```

## Chart Rendering Explained

### What are .htpl files?

The source code has "meta-template" files (`.htpl`) that are pre-processed before becoming actual Helm templates:

```
image/templates/helm/stackrox-central/
├── Chart.yaml.htpl              # Meta-template
├── values.yaml.htpl             # Meta-template
└── templates/
    ├── deployment.yaml.htpl     # Meta-template
    └── service.yaml.htpl        # Meta-template
```

### What roxctl helm output does:

1. **Merge shared templates** from `image/templates/helm/shared/`
2. **Render .htpl files** using feature flags and build info
3. **Output standard Helm chart**:
   ```
   helm-output/stackrox-central-services-chart/
   ├── Chart.yaml                 # Rendered
   ├── values.yaml                # Rendered
   └── templates/
       ├── deployment.yaml        # Rendered
       └── service.yaml           # Rendered
   ```

### Why is this faster?

`roxctl helm output`:
* Runs locally (if you have roxctl installed)
* Only renders templates (no image pulling, no full generation)
* Produces reusable chart

`roxctl central generate`:
* Often runs in Docker (image pull overhead)
* Generates everything including baked-in values
* Less reusable

## Workflow Comparison

### Development Iteration with Source Charts

```bash
# Day 1: Initial deployment
./deploy-from-source.sh abc123 4.6.x-nightly-20241003
# Time: ~1 minute (roxctl helm output + Helm deploy)

# Day 2-30: Image updates (chart already rendered!)
helm upgrade stackrox-central-services \
  ./helm-output/stackrox-central-services-chart/ \
  --reuse-values --set image.tag=abc124
# Time: ~10 seconds (Helm only)

# Or even faster with kubectl:
./update-main-image.sh abc124
# Time: ~30 seconds (kubectl only)
```

### Development Iteration with deploy-custom-main.sh

```bash
# Day 1: Initial deployment
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
# Time: ~3-5 minutes (roxctl central generate + Helm deploy)

# Day 2-30: Image updates
./update-main-image.sh abc124
# Time: ~30 seconds (kubectl only)
```

## When to Use Each Approach

### Use deploy-from-source.sh when:
* ✅ You have the source code checked out
* ✅ You're actively developing StackRox itself
* ✅ You want the fastest initial deployment
* ✅ You want full control over Helm values
* ✅ You're testing chart changes

### Use deploy-custom-main.sh when:
* ✅ You don't have source code
* ✅ You're just deploying with custom images
* ✅ You want simpler script interface
* ✅ You don't need to modify charts

### Use update-main-image.sh when:
* ✅ Iterating on code changes (either approach)
* ✅ Want fastest possible updates
* ✅ Only changing image tags

## Advanced: Manual Chart Rendering

If you want full control:

```bash
# 1. Render chart from source
roxctl helm output central-services \
  --output-dir ./my-charts \
  --image-defaults=development_build

# 2. Customize the chart itself (optional)
# Edit files in ./my-charts/stackrox-central-services-chart/

# 3. Create custom values
cat > my-values.yaml <<EOF
image:
  registry: localhost:5001
  name: stackrox/main
  tag: abc123

central:
  db:
    image:
      registry: quay.io
      name: rhacs-eng/central-db
      tag: 4.6.x-nightly-20241003

# ... more custom values ...
EOF

# 4. Deploy
helm upgrade --install stackrox-central-services \
  ./my-charts/stackrox-central-services-chart/ \
  --namespace stackrox \
  --create-namespace \
  --values my-values.yaml \
  --wait

# 5. Update later (chart already rendered)
helm upgrade stackrox-central-services \
  ./my-charts/stackrox-central-services-chart/ \
  --reuse-values \
  --set image.tag=abc124
```

## Modifying Source Charts

If you're developing chart changes:

```bash
# 1. Edit chart templates
vim image/templates/helm/stackrox-central/templates/deployment.yaml.htpl

# 2. Render updated chart
roxctl helm output central-services \
  --output-dir ./test-charts \
  --debug

# 3. Test deployment
helm upgrade --install test-central \
  ./test-charts/stackrox-central-services-chart/ \
  --namespace test \
  --values test-values.yaml

# 4. Iterate quickly
# Edit, render, upgrade, repeat
```

## Performance Benchmarks

Based on local testing:

| Operation | Time | roxctl Needed | Chart Reusable |
|-----------|------|---------------|----------------|
| `roxctl central generate` | ~30s | ✅ Docker | ❌ No |
| `roxctl helm output` (local) | ~5s | ✅ Local | ✅ Yes |
| `roxctl helm output` (Docker) | ~15s | ✅ Docker | ✅ Yes |
| Helm update (reuse chart) | ~10s | ❌ No | N/A |
| kubectl set image | ~30s | ❌ No | N/A |

**Best practice**: Render chart once with `roxctl helm output`, then reuse for all updates.

## Chart Caching Strategy

```bash
# Setup: Render chart once per nightly version
NIGHTLY="4.6.x-nightly-20241003"
CHART_CACHE="$HOME/.stackrox-charts/$NIGHTLY"

# Create cached chart
mkdir -p "$CHART_CACHE"
roxctl helm output central-services \
  --output-dir "$CHART_CACHE"

# Use cached chart for all deployments
helm upgrade --install stackrox-central-services \
  "$CHART_CACHE/stackrox-central-services-chart/" \
  --set image.tag=abc123
  # ... repeat with different tags ...

# When nightly version changes, re-render
NIGHTLY="4.6.x-nightly-20241010"
CHART_CACHE="$HOME/.stackrox-charts/$NIGHTLY"
# ... render new chart ...
```

## Integration with Existing Scripts

### Option 1: Pre-render chart, use with deploy-custom-main.sh

```bash
# Pre-render chart
roxctl helm output central-services --output-dir ./helm-charts

# Set environment to use pre-rendered chart
export CENTRAL_CHART_DIR_OVERRIDE="./helm-charts/stackrox-central-services-chart"

# Use existing script
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003
# Will use your pre-rendered chart instead of generating
```

### Option 2: Hybrid approach

```bash
# For initial deployment or major changes
./deploy-custom-main.sh abc123 4.6.x-nightly-20241003

# For iterations
./update-main-image.sh abc124
./update-main-image.sh abc125

# For chart updates only
roxctl helm output central-services --output-dir ./new-charts
helm upgrade stackrox-central-services ./new-charts/... --reuse-values
```

## Source Chart Documentation

See the source code for detailed chart documentation:

* `image/templates/README.md` - Overview and workflow
* `image/templates/CHANGING_CHARTS.md` - How to modify charts
* `image/templates/CHART_TEMPLATING.md` - Templating details
* `image/templates/helm/stackrox-central/README.md.htpl` - Central chart docs
* `image/templates/helm/stackrox-secured-cluster/README.md.htpl` - Sensor chart docs

## Summary

**Using source charts gives you**:
* ✅ Faster rendering (~5s vs ~30s)
* ✅ Reusable chart for quick updates
* ✅ Full Helm values control
* ✅ Ability to modify charts
* ✅ Better for active development

**The `deploy-from-source.sh` script**:
* Renders chart from source using `roxctl helm output`
* Saves chart to `./helm-output/` for reuse
* Deploys with your custom image configuration
* Enables fast updates via Helm values

**For fastest iteration**:
1. Use `deploy-from-source.sh` once (renders chart)
2. Use `update-main-image.sh` for image changes (no roxctl, no Helm)
3. Use chart in `./helm-output/` for value changes (no roxctl)
