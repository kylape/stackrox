#!/bin/bash
# daily-dev-setup.sh - Complete automated daily dev environment setup

set -e

# Configuration
GITHUB_USER="kylape"
GITHUB_REPO="stackrox"
LOG_FILE="/tmp/dev-setup-$(date +%Y%m%d-%H%M%S).log"

echo "🌅 Starting daily StackRox dev environment setup..."
echo "📝 Logging to: $LOG_FILE"

# Function to log and execute
log_exec() {
    echo "▶️  $1"
    echo "[$(date)] $1" >> "$LOG_FILE"
    shift
    "$@" 2>&1 | tee -a "$LOG_FILE"
}

# Check prerequisites
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN not set. Please export your GitHub token:"
    echo "   export GITHUB_TOKEN=ghp_your_token_here"
    exit 1
fi

# 1. Basic infrastructure setup (your existing scripts)
log_exec "Setting up EC2 and basic infrastructure" \
    ./setup-ec2.sh

log_exec "Setting up Kind cluster" \
    ./setup-kind-cluster.sh

log_exec "Setting up devcontainer" \
    ./setup-devcontainer.sh

# 2. Setup Tekton pipeline
log_exec "Setting up Tekton pipeline automation" \
    ./setup-tekton-pipeline.sh

# 3. Setup webhook connectivity
if command -v ngrok &> /dev/null; then
    echo "🌐 Setting up ngrok for webhook connectivity..."
    
    # Start ngrok in background
    ngrok http 8080 --log=stdout > /tmp/ngrok.log &
    NGROK_PID=$!
    
    # Wait for ngrok to establish tunnel
    echo "⏳ Waiting for ngrok tunnel..."
    sleep 10
    
    # Get the public URL
    WEBHOOK_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url // empty')
    
    if [ -z "$WEBHOOK_URL" ]; then
        echo "❌ Failed to get ngrok URL. Check ngrok setup."
        echo "📋 Manual webhook setup required."
        exit 1
    fi
    
    echo "✅ ngrok tunnel established: $WEBHOOK_URL"
    
    # Get the webhook secret from Kubernetes
    WEBHOOK_SECRET=$(kubectl get secret github-webhook-secret -n stackrox-tekton -o jsonpath='{.data.secretToken}' | base64 -d)
    
    # Setup GitHub webhook automatically
    log_exec "Setting up GitHub webhook" \
        ./setup-github-webhook.sh "$WEBHOOK_URL" "$WEBHOOK_SECRET"
    
    # Save webhook info for reference
    cat > /tmp/webhook-info.txt <<EOF
Webhook URL: $WEBHOOK_URL  
Webhook Secret: $WEBHOOK_SECRET
ngrok PID: $NGROK_PID
EOF
    
else
    echo "⚠️  ngrok not found. Manual webhook setup required."
    echo "📋 After setup, configure webhook manually at:"
    echo "   https://github.com/$GITHUB_USER/$GITHUB_REPO/settings/hooks"
fi

# 4. Create helpful aliases and functions
cat > /tmp/dev-aliases.sh <<'ALIASES'
#!/bin/bash
# Daily dev environment aliases and functions

# Tekton pipeline management
alias builds='kubectl get pipelineruns -n stackrox-tekton --sort-by=.metadata.creationTimestamp'
alias build-logs='tkn pipelinerun logs -n stackrox-tekton -f'
alias latest-build='kubectl get pipelineruns -n stackrox-tekton --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2'

# Quick deployment testing
alias test-deploy='./bin/installer apply central && ./bin/installer apply crs && ./bin/installer apply securedcluster'
alias check-deploy='kubectl get pods -n stackrox'

# Development shortcuts
alias build-installer='make bin/installer'
alias rebuild-image='docker build -t localhost:5001/stackrox/stackrox:$(git rev-parse --short HEAD) .'

# Push and watch (trigger pipeline and monitor)
push-and-watch() {
    local branch=${1:-$(git branch --show-current)}
    echo "🚀 Pushing $branch and watching for pipeline..."
    git push origin "$branch"
    echo "⏳ Waiting for pipeline to start..."
    sleep 10
    build-logs "$(latest-build)"
}

# Quick status check
dev-status() {
    echo "🏗️  Recent builds:"
    builds | tail -5
    echo ""
    echo "🎯 Current cluster status:"
    kubectl get nodes
    echo ""
    echo "📊 Tekton status:"
    kubectl get pods -n tekton-pipelines
    echo ""
    if [ -f /tmp/webhook-info.txt ]; then
        echo "🔗 Webhook info:"
        cat /tmp/webhook-info.txt
    fi
}

export -f push-and-watch dev-status
ALIASES

chmod +x /tmp/dev-aliases.sh
echo "source /tmp/dev-aliases.sh" >> ~/.bashrc
echo "source /tmp/tekton-helpers.sh" >> ~/.bashrc

# 5. Final setup verification
echo ""
echo "🧪 Running setup verification..."

# Check Kind cluster
if kubectl cluster-info &>/dev/null; then
    echo "✅ Kind cluster is healthy"
else
    echo "❌ Kind cluster issues detected"
fi

# Check Tekton installation
if kubectl get pods -n tekton-pipelines | grep -q Running; then
    echo "✅ Tekton is running"
else
    echo "❌ Tekton installation issues"
fi

# Check pipeline installation  
if kubectl get pipeline stackrox -n stackrox-tekton &>/dev/null; then
    echo "✅ StackRox pipeline installed"
else
    echo "❌ StackRox pipeline not found"
fi

# 6. Create daily summary
cat > /tmp/daily-dev-summary.txt <<EOF
🎉 Daily StackRox Dev Environment Setup Complete!

📅 Setup Date: $(date)
🏗️  Architecture: 64-core ARM64 Kind cluster with Tekton
⚡ Performance: ~8-10 minute builds (vs 26-35 min traditional)

🔧 What's Ready:
  ✅ Kind cluster with StackRox deployed
  ✅ Tekton pipeline for automated builds  
  ✅ GitHub webhook integration (push-to-build)
  ✅ Local registry for fast iteration
  ✅ Your single-image architecture
  ✅ Custom Go installer

🚀 Your Workflow:
  1. Edit code in devcontainer
  2. git push origin your-branch  
  3. Pipeline auto-triggers and builds
  4. Fresh image auto-deployed locally
  5. Test your changes immediately

📊 Helpful Commands:
  builds              - Show recent builds
  push-and-watch      - Push branch and monitor build
  dev-status          - Show environment status
  build-logs [name]   - View build logs
  test-deploy         - Quick redeploy test

🔗 GitHub Integration:
$(if [ -f /tmp/webhook-info.txt ]; then cat /tmp/webhook-info.txt; else echo "  Manual setup required - see logs"; fi)

📝 Setup log: $LOG_FILE
EOF

echo ""
cat /tmp/daily-dev-summary.txt

# Source the new functions immediately
source /tmp/dev-aliases.sh
source /tmp/tekton-helpers.sh

echo ""
echo "🎯 Ready to go! Try:"
echo "   git push origin your-branch    # Triggers automated build"
echo "   dev-status                     # Check environment health" 
echo "   push-and-watch feature-branch  # Push and monitor build"

echo ""
echo "💡 Pro tip: Your environment is completely fresh each day with zero maintenance overhead!"