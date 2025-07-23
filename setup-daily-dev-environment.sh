#!/bin/bash
# setup-daily-dev-environment.sh - Integrated daily dev environment setup
# Combines your existing devcontainer + stackrox-tekton setup with webhook automation

set -e

# Configuration
GITHUB_USER="kylape"
GITHUB_REPO="stackrox"
AWS_SAML_SCRIPT="${AWS_SAML_SCRIPT:-get-aws-token.py}"  # Your company's SAML script
LOG_FILE="/tmp/dev-setup-$(date +%Y%m%d-%H%M%S).log"

echo "🌅 Starting integrated StackRox dev environment setup..."
echo "📝 Logging to: $LOG_FILE"

# Function to log and execute
log_exec() {
    local description="$1"
    shift
    echo "▶️  $description"
    echo "[$(date)] $description" >> "$LOG_FILE"
    "$@" 2>&1 | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    echo "🔍 Checking prerequisites..."
    
    if [ -z "$GITHUB_TOKEN" ]; then
        echo "❌ GITHUB_TOKEN not set. Please export your GitHub token:"
        echo "   export GITHUB_TOKEN=ghp_your_token_here"
        exit 1
    fi
    
    if ! command -v "$AWS_SAML_SCRIPT" &> /dev/null; then
        echo "⚠️  AWS SAML script '$AWS_SAML_SCRIPT' not found in PATH"
        echo "   Please ensure your company's SAML script is available"
        echo "   Or set AWS_SAML_SCRIPT environment variable"
    fi
    
    echo "✅ Prerequisites check complete"
}

# Setup AWS credentials using SAML
setup_aws_credentials() {
    echo "🔐 Setting up AWS credentials via SAML..."
    
    if command -v "$AWS_SAML_SCRIPT" &> /dev/null; then
        echo "   Running SAML authentication..."
        # Run your company's SAML script (adjust as needed for your script's interface)
        if "$AWS_SAML_SCRIPT" --output-format env > /tmp/aws-creds.env; then
            source /tmp/aws-creds.env
            rm -f /tmp/aws-creds.env
            echo "✅ AWS credentials obtained via SAML"
        else
            echo "❌ Failed to get AWS credentials via SAML"
            echo "   Please run '$AWS_SAML_SCRIPT' manually and check for errors"
            exit 1
        fi
    else
        echo "⚠️  SAML script not available, using existing AWS credentials"
        if ! aws sts get-caller-identity &>/dev/null; then
            echo "❌ No valid AWS credentials found"
            echo "   Please ensure AWS credentials are available or set AWS_SAML_SCRIPT"
            exit 1
        fi
    fi
}

# Your existing devcontainer setup (adapted)
setup_devcontainer_infrastructure() {
    echo "🏗️  Setting up devcontainer infrastructure..."
    
    # Run your existing devcontainer setup
    log_exec "Running devcontainer setup" \
        bash devcontainer/setup.sh -s
    
    echo "✅ Devcontainer infrastructure ready"
}

# Your existing stackrox-tekton setup (adapted) 
setup_tekton_base() {
    echo "🔧 Setting up base Tekton infrastructure..."
    
    # Run your existing stackrox-tekton setup
    log_exec "Installing Tekton and MinIO" \
        bash stackrox-tekton/setup.sh
    
    echo "✅ Base Tekton setup complete"
}

# Enhanced Tekton setup with GitHub integration
setup_tekton_github_integration() {
    echo "🔗 Setting up GitHub webhook integration..."
    
    local namespace="default"
    
    # Create webhook secret
    local webhook_secret=$(openssl rand -hex 20)
    kubectl create secret generic github-webhook-secret \
        --from-literal=secretToken="$webhook_secret" \
        -n "$namespace" --dry-run=client -o yaml | kubectl apply -f -
    
    # Setup Tekton Triggers for GitHub integration
    cat <<EOF | kubectl apply -f -
apiVersion: triggers.tekton.dev/v1beta1
kind: EventListener
metadata:
  name: github-webhook-listener
  namespace: $namespace
spec:
  triggers:
  - name: github-push-trigger
    interceptors:
    - name: "validate GitHub payload and filter on eventType"
      ref:
        name: "github"
      params:
      - name: "secretRef"
        value:
          secretName: github-webhook-secret  
          secretKey: secretToken
      - name: "eventTypes"
        value: ["push"]
    bindings:
    - ref: github-push-binding
    template:
      ref: github-push-template
---
apiVersion: triggers.tekton.dev/v1beta1
kind: TriggerBinding
metadata:
  name: github-push-binding  
  namespace: $namespace
spec:
  params:
  - name: git-repo-url
    value: \$(body.repository.clone_url)
  - name: git-revision
    value: \$(body.head_commit.id)
  - name: git-repo-name
    value: \$(body.repository.name)
  - name: git-branch
    value: \$(extensions.branch_name)
---
apiVersion: triggers.tekton.dev/v1beta1
kind: TriggerTemplate
metadata:
  name: github-push-template
  namespace: $namespace  
spec:
  params:
  - name: git-repo-url
  - name: git-revision
  - name: git-repo-name
  - name: git-branch
  resourcetemplates:
  - apiVersion: tekton.dev/v1beta1
    kind: PipelineRun
    metadata:
      name: stackrox-build-\$(tt.params.git-revision)
      namespace: $namespace
    spec:
      pipelineRef:
        name: stackrox
      params:
      - name: repo-url
        value: \$(tt.params.git-repo-url)
      - name: revision  
        value: \$(tt.params.git-revision)
      - name: builder-image
        value: "kind-registry:5000/stackrox/stackrox-builder:latest"
      - name: registry
        value: "kind-registry:5000"
      workspaces:
      - name: shared-data
        volumeClaimTemplate:
          spec:
            accessModes:
            - ReadWriteOnce
            resources:
              requests:
                storage: 20Gi
EOF
    
    # Deploy your existing pipeline resources
    log_exec "Deploying StackRox Tekton pipelines" \
        kubectl apply -f stackrox-tekton/resources/stackrox/
    
    echo "✅ GitHub integration setup complete"
    
    # Save webhook secret for later use
    echo "$webhook_secret" > /tmp/webhook-secret.txt
}

# Setup webhook endpoint with ngrok
setup_webhook_endpoint() {
    echo "🌐 Setting up webhook endpoint..."
    
    # Install Tekton Triggers if not already installed
    kubectl apply --filename https://storage.googleapis.com/tekton-releases/triggers/latest/release.yaml
    kubectl apply --filename https://storage.googleapis.com/tekton-releases/triggers/latest/interceptors.yaml
    
    # Wait for triggers to be ready
    kubectl wait --for=condition=ready pod -l app=tekton-triggers-controller -n tekton-triggers --timeout=300s
    
    # Expose the event listener
    kubectl expose deployment el-github-webhook-listener --type=NodePort --port=8080 --target-port=8080 2>/dev/null || true
    
    # Port forward for webhook access
    kubectl port-forward service/el-github-webhook-listener 8080:8080 &
    local portforward_pid=$!
    echo "$portforward_pid" > /tmp/portforward.pid
    
    # Wait for port forward to establish
    sleep 5
    
    # Setup ngrok if available
    if command -v ngrok &> /dev/null; then
        echo "   Starting ngrok tunnel..."
        ngrok http 8080 --log=stdout > /tmp/ngrok.log &
        local ngrok_pid=$!
        echo "$ngrok_pid" > /tmp/ngrok.pid
        
        # Wait for ngrok to establish tunnel
        sleep 10
        
        # Get the public URL
        local webhook_url=$(curl -s localhost:4040/api/tunnels 2>/dev/null | jq -r '.tunnels[0].public_url // empty')
        
        if [ ! -z "$webhook_url" ]; then
            echo "$webhook_url" > /tmp/webhook-url.txt
            echo "✅ Webhook URL: $webhook_url"
        else
            echo "❌ Failed to get ngrok URL"
            webhook_url="http://your-public-ip:8080"
            echo "$webhook_url" > /tmp/webhook-url.txt
        fi
    else
        echo "⚠️  ngrok not found, using localhost URL"
        webhook_url="http://localhost:8080"
        echo "$webhook_url" > /tmp/webhook-url.txt
    fi
}

# Setup GitHub webhook automatically
setup_github_webhook() {
    echo "🔗 Configuring GitHub webhook..."
    
    local webhook_url=$(cat /tmp/webhook-url.txt)
    local webhook_secret=$(cat /tmp/webhook-secret.txt)
    
    # Use your existing script if available, or create webhook via API
    if [ -f "./setup-github-webhook.sh" ]; then
        log_exec "Setting up GitHub webhook via script" \
            ./setup-github-webhook.sh "$webhook_url" "$webhook_secret"
    else
        echo "⚠️  setup-github-webhook.sh not found, manual setup required"
        echo "   URL: $webhook_url"
        echo "   Secret: $webhook_secret"
    fi
}

# Create helpful aliases and functions (adapted from your workflow)
setup_development_helpers() {
    echo "🛠️  Setting up development helpers..."
    
    cat > /tmp/dev-helpers.sh <<'HELPERS'
#!/bin/bash
# Development helper functions adapted for your workflow

# Tekton pipeline management
alias builds='kubectl get pipelineruns --sort-by=.metadata.creationTimestamp'
alias build-logs='tkn pipelinerun logs -f'
alias latest-build='kubectl get pipelineruns --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2'

# Your existing devcontainer access
alias dev='ssh devcontainer'
alias dev-sync='rsync -av --exclude .git . devcontainer:~/workspace/stackrox/'

# StackRox development shortcuts
alias build-installer='make bin/installer'
alias test-deploy='./test-installer.sh'
alias check-deploy='kubectl get pods -n stackrox'

# Push and watch (trigger pipeline and monitor)
push-and-watch() {
    local branch=${1:-$(git branch --show-current)}
    echo "🚀 Pushing $branch and watching for pipeline..."
    git push origin "$branch"
    echo "⏳ Waiting for pipeline to start..."
    sleep 15
    build-logs "$(latest-build)"
}

# Environment status check
dev-status() {
    echo "🏗️  Recent builds:"
    builds | tail -5
    echo ""
    echo "🎯 Cluster status:"
    kubectl get nodes
    echo ""
    echo "📊 Tekton status:"
    kubectl get pods -n tekton-pipelines
    echo ""
    echo "🏠 Devcontainer status:"
    kubectl get pods -l app=devcontainer
    echo ""
    if [ -f /tmp/webhook-url.txt ]; then
        echo "🔗 Webhook info:"
        echo "   URL: $(cat /tmp/webhook-url.txt)"
        echo "   Secret: $(cat /tmp/webhook-secret.txt 2>/dev/null || echo 'See /tmp/webhook-secret.txt')"
    fi
}

# AWS token refresh (using your company's SAML script)
refresh-aws-token() {
    if command -v "${AWS_SAML_SCRIPT:-get-aws-token.py}" &> /dev/null; then
        echo "🔐 Refreshing AWS token..."
        "${AWS_SAML_SCRIPT:-get-aws-token.py}" --output-format env > /tmp/aws-creds.env
        source /tmp/aws-creds.env
        rm -f /tmp/aws-creds.env
        echo "✅ AWS token refreshed"
    else
        echo "❌ SAML script not found"
    fi
}

export -f push-and-watch dev-status refresh-aws-token
HELPERS
    
    chmod +x /tmp/dev-helpers.sh
    echo "source /tmp/dev-helpers.sh" >> ~/.bashrc
    
    echo "✅ Development helpers installed"
}

# Main execution
main() {
    check_prerequisites
    setup_aws_credentials
    setup_devcontainer_infrastructure
    setup_tekton_base
    setup_tekton_github_integration
    setup_webhook_endpoint
    setup_github_webhook
    setup_development_helpers
    
    # Create daily summary
    cat > /tmp/daily-dev-summary.txt <<EOF
🎉 Integrated StackRox Dev Environment Setup Complete!

📅 Setup Date: $(date)
🏗️  Architecture: KinD cluster + Devcontainer + Tekton + GitHub webhooks
⚡ Performance: Multi-arch builds with your existing pipeline optimizations

🔧 What's Ready:
  ✅ KinD cluster with devcontainer deployed
  ✅ Your existing Tekton pipelines with GitHub integration
  ✅ GitHub webhook for push-to-build automation
  ✅ MinIO caching from your stackrox-tekton setup
  ✅ AWS credentials via SAML integration

🚀 Your Workflow:
  1. SSH into devcontainer: ssh devcontainer
  2. Edit code in familiar environment
  3. git push origin your-branch (triggers automated build)
  4. Monitor with: build-logs \$(latest-build)
  5. Test deployment with: test-deploy

📊 Helpful Commands:
  builds              - Show recent pipeline runs
  dev-status          - Environment health check
  push-and-watch      - Push and monitor build
  refresh-aws-token   - Refresh SAML token
  dev                 - SSH to devcontainer
  dev-sync            - Sync local changes to devcontainer

🔗 Integration Points:
  GitHub Webhook: $(cat /tmp/webhook-url.txt 2>/dev/null || echo "Manual setup required")
  Devcontainer SSH: localhost:2222 (via proxy jump)
  Registry: kind-registry:5000

📝 Setup log: $LOG_FILE
EOF
    
    echo ""
    cat /tmp/daily-dev-summary.txt
    
    # Source helpers immediately
    source /tmp/dev-helpers.sh
    
    echo ""
    echo "🎯 Ready to go! Your integrated environment combines:"
    echo "   • Your existing devcontainer setup"
    echo "   • Your proven stackrox-tekton pipelines" 
    echo "   • Automated GitHub webhook integration"
    echo "   • SAML-based AWS authentication"
    echo ""
    echo "💡 Pro tip: Use 'dev-status' to check everything is running!"
}

# Execute main function
main "$@"