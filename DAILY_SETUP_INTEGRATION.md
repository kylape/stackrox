# Daily Development Environment Integration

This document explains how the new automated daily setup scripts integrate with your existing devcontainer and stackrox-tekton workflows.

## Overview

The new scripts enhance your existing setup by adding:
- **GitHub webhook integration** for push-to-build automation
- **SAML-based AWS authentication** 
- **Automated daily provisioning** that combines your proven patterns
- **Preserved workflow** using your existing devcontainer and tekton setups

## Your Existing Workflow (Preserved)

### Current Pattern
```bash
# Your existing daily workflow
./devcontainer/run-setup.sh ~/.ssh/ec2-key.pem ec2-hostname
ssh devcontainer    # Your familiar development environment
```

### What Gets Preserved
- ✅ **devcontainer setup** - Your existing `devcontainer/setup.sh` runs unchanged
- ✅ **stackrox-tekton pipelines** - Your proven `stackrox-tekton/setup.sh` setup
- ✅ **SSH proxy jump** - Same devcontainer access pattern
- ✅ **KinD cluster** - Your existing cluster configuration  
- ✅ **MinIO caching** - Your existing pipeline caching setup

## New Enhanced Workflow

### One-Time Laptop Setup
```bash
# Set your GitHub token (one time)
export GITHUB_TOKEN=ghp_your_token_here

# Optional: Set path to your company's SAML script
export AWS_SAML_SCRIPT=/path/to/get-aws-token.py
```

### Daily Morning Setup
```bash
# Replace your existing run-setup.sh with the enhanced version
./run-daily-setup.sh ~/.ssh/ec2-key.pem ec2-hostname
```

**What this does:**
1. **Runs your existing setup** - All your current devcontainer + tekton setup
2. **Adds GitHub integration** - Configures webhooks for push-to-build
3. **Handles AWS authentication** - Runs your company's SAML script
4. **Sets up automation** - Pipeline triggers on every git push

### Your Development Cycle (Enhanced)
```bash
# Connect to your familiar devcontainer 
ssh devcontainer

# Develop as usual in your devcontainer
vim central/somefeature.go

# Push triggers automatic build (NEW!)
git push origin feature-branch
# 🚀 Pipeline automatically starts building
# ⏳ 8-10 minutes later: fresh image ready

# Test your changes
./test-installer.sh
```

## Integration Architecture

```
Laptop (MacBook)                    EC2 Instance (Daily Fresh)
├── run-daily-setup.sh          ┌─→ ├── devcontainer/setup.sh (existing)
├── AWS SAML script              │   ├── stackrox-tekton/setup.sh (existing)  
├── GitHub token                 │   ├── setup-daily-dev-environment.sh (new)
└── SSH config                   └── └── GitHub webhook integration (new)
                                         └── Your familiar devcontainer environment
```

## File Structure Integration

### Your Existing Files (Unchanged)
```
stackrox/
├── devcontainer/
│   ├── setup.sh                 # ✅ Runs unchanged
│   ├── run-setup.sh             # ✅ Pattern preserved in new script
│   └── resources/               # ✅ Used unchanged
├── stackrox-tekton/
│   ├── setup.sh                 # ✅ Runs unchanged  
│   └── resources/               # ✅ Your proven pipelines
└── test-installer.sh            # ✅ Works unchanged
```

### New Integration Files
```
stackrox/
├── run-daily-setup.sh           # 🆕 Enhanced version of your run-setup.sh
├── setup-daily-dev-environment.sh  # 🆕 Orchestrates everything
├── setup-github-webhook.sh      # 🆕 Automates webhook setup
└── DAILY_SETUP_INTEGRATION.md   # 🆕 This document
```

## SAML Integration Details

### Your Company's SAML Script
```bash
# The integration expects your script to:
# 1. Accept --output-format env flag
# 2. Output AWS credentials in env format:
#    export AWS_ACCESS_KEY_ID=...
#    export AWS_SECRET_ACCESS_KEY=...
#    export AWS_SESSION_TOKEN=...

# Example usage in the integration:
get-aws-token.py --output-format env > /tmp/aws-creds.env
source /tmp/aws-creds.env
```

### Configuration Options
```bash
# Method 1: Environment variable
export AWS_SAML_SCRIPT=/path/to/your-companies-script.py
./run-daily-setup.sh keyfile hostname

# Method 2: Command line option  
./run-daily-setup.sh keyfile hostname --aws-script /path/to/script.py

# Method 3: Default assumption
# Script looks for 'get-aws-token.py' in PATH
```

## GitHub Integration Details

### Webhook Automation
- **Automatic setup** - Script creates webhook pointing to your EC2 instance
- **ngrok integration** - Uses ngrok if available for public URL
- **Secret management** - Generates secure webhook secret automatically
- **Push triggers** - Every push to your fork triggers a pipeline run

### Manual Fallback
If automatic webhook setup fails:
1. Script outputs webhook URL and secret
2. Manually add at: https://github.com/kylape/stackrox/settings/hooks
3. Use the provided URL and secret

## Development Helper Functions

Your enhanced environment includes these new commands:

```bash
# Pipeline management (integrated with your existing tekton)
builds                    # Show recent pipeline runs  
build-logs $(latest-build) # Show logs for latest build
push-and-watch branch     # Push and monitor build

# Environment status
dev-status               # Check all services (devcontainer, tekton, etc)
refresh-aws-token        # Re-run SAML authentication

# Your existing patterns still work
ssh devcontainer         # Your familiar environment
./test-installer.sh      # Your existing deployment test
make bin/installer       # Your existing build commands
```

## Benefits of Integration

### What You Keep
- **Zero learning curve** - Same devcontainer environment and SSH access
- **Proven pipelines** - Your working stackrox-tekton setup
- **Familiar tools** - Same development environment and commands
- **Debugging access** - Same kubectl access and cluster interaction

### What You Gain  
- **Push-to-build** - Automatic pipeline triggers on git push
- **AWS integration** - SAML authentication handled automatically
- **Automation** - Daily fresh environment with zero manual steps
- **GitHub integration** - Webhook setup and management automated

## Troubleshooting

### Common Issues
```bash
# Check if your existing components are working
ssh devcontainer -c "kubectl get nodes"           # Test cluster
ssh devcontainer -c "kubectl get pods -l app=devcontainer"  # Test container
ssh devcontainer -c "builds"                      # Test pipelines

# Refresh AWS credentials if needed
ssh devcontainer -c "refresh-aws-token"

# Check webhook status
ssh devcontainer -c "kubectl get pods -l eventlistener=github-webhook-listener"
```

### Fallback Options
- **Manual webhook setup** - If automation fails, script provides manual instructions
- **Existing workflow** - Your original devcontainer setup still works independently
- **AWS manual auth** - Can skip SAML integration and use existing AWS credentials

## Migration Path

### Phase 1: Test Integration (Low Risk)
```bash
# Test the new setup alongside your existing workflow
./run-daily-setup.sh keyfile hostname

# Verify everything works
ssh devcontainer
# Use familiar environment, test new features
```

### Phase 2: Adopt New Workflow (When Comfortable)
```bash
# Replace morning routine
# Old: ./devcontainer/run-setup.sh keyfile hostname  
# New: ./run-daily-setup.sh keyfile hostname

# Everything else stays the same
```

### Phase 3: Enjoy Automation
```bash
# Your development cycle becomes:
git push origin feature-branch    # Automatic build starts
ssh devcontainer -c "build-logs $(latest-build)"  # Monitor if desired
# Build completes automatically, deploy when ready
```

## Summary

The integration **enhances your existing workflow without breaking it**. Your proven devcontainer and stackrox-tekton setups remain unchanged, but now you get:

- **Automated GitHub integration** for push-to-build workflows
- **SAML authentication** for seamless AWS access  
- **Daily fresh environments** with zero maintenance overhead
- **Same familiar development experience** you already know

The scripts follow your existing patterns (`run-setup.sh` → `run-daily-setup.sh`) while adding the automation and integration capabilities discussed in our analysis.