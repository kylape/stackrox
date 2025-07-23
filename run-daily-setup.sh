#!/bin/bash
# run-daily-setup.sh - Laptop-side orchestration for daily dev environment
# Follows your existing run-setup.sh pattern but adds Tekton + GitHub integration

set -e

# Check arguments
if [[ "$1" == "" ]]; then
    echo "Usage: $0 <keyfile> <hostname> [options]"
    echo ""
    echo "Arguments:"
    echo "  keyfile   - SSH private key file for EC2 access"
    echo "  hostname  - EC2 instance hostname/IP"
    echo ""
    echo "Options:"
    echo "  --aws-script <script>  - Path to your company's AWS SAML script"
    echo "  --github-token <token> - GitHub token (or set GITHUB_TOKEN env var)"
    echo ""
    echo "Example:"
    echo "  $0 ~/.ssh/ec2-key.pem ec2-12-34-56-78.compute-1.amazonaws.com"
    exit 1
fi

if [[ "$2" == "" ]]; then
    echo "Provide hostname"
    exit 1
fi

keyfile=$1
hostname=$2
shift 2

# Parse additional options
aws_script=""
github_token="${GITHUB_TOKEN:-}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --aws-script)
            aws_script="$2"
            shift 2
            ;;
        --github-token)
            github_token="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate GitHub token
if [[ -z "$github_token" ]]; then
    echo "❌ GitHub token required. Either:"
    echo "   export GITHUB_TOKEN=ghp_your_token_here"
    echo "   or use --github-token option"
    exit 1
fi

echo "🚀 Setting up daily StackRox dev environment on $hostname"
echo "📦 Preparing deployment package..."

# Create temporary directory for deployment package
deploy_dir=$(mktemp -d)
trap "rm -rf $deploy_dir" EXIT

# Package up the setup files (following your existing pattern)
echo "   Packaging setup files..."
tar cvf "$deploy_dir/setup.tar" \
    devcontainer/ \
    stackrox-tekton/ \
    setup-daily-dev-environment.sh \
    setup-github-webhook.sh \
    tekton/ 2>/dev/null || echo "Note: Some directories may not exist yet"

# Create environment setup script
cat > "$deploy_dir/setup-env.sh" <<EOF
#!/bin/bash
# Environment setup for remote execution

export GITHUB_TOKEN="$github_token"
export AWS_SAML_SCRIPT="$aws_script"

# Extract setup files
cd /tmp
tar xf setup.tar

# Make scripts executable
chmod +x setup-daily-dev-environment.sh setup-github-webhook.sh

echo "🎯 Starting integrated dev environment setup..."
./setup-daily-dev-environment.sh
EOF

chmod +x "$deploy_dir/setup-env.sh"

# Copy deployment package to remote host
echo "📤 Deploying to remote host..."
scp -i "$keyfile" "$deploy_dir/setup.tar" "$deploy_dir/setup-env.sh" "fedora@$hostname:/tmp/"

# Execute setup on remote host
echo "🔧 Executing remote setup..."
ssh -i "$keyfile" fedora@$hostname "cd /tmp && ./setup-env.sh"

# Extract SSH configuration for devcontainer access
echo ""
echo "📋 SSH Configuration for your ~/.ssh/config:"
echo ""
cat << EOF
Host devcontainer
    HostName localhost
    Port 2222
    User root
    ProxyJump ec2host
    DynamicForward 8080
    RemoteCommand /usr/bin/zsh
    RequestTTY yes
    LogLevel QUIET

Host ec2host
    HostName $hostname
    User fedora
    Port 22
    IdentityFile $keyfile
EOF

# Check if setup was successful
echo ""
echo "🧪 Verifying setup..."
if ssh -i "$keyfile" fedora@$hostname "kubectl get nodes" &>/dev/null; then
    echo "✅ Kubernetes cluster is accessible"
else
    echo "❌ Kubernetes cluster setup may have failed"
fi

if ssh -i "$keyfile" fedora@$hostname "kubectl get pods -l app=devcontainer" &>/dev/null; then
    echo "✅ Devcontainer is deployed"
else
    echo "❌ Devcontainer deployment may have failed"
fi

if ssh -i "$keyfile" fedora@$hostname "kubectl get pipelineruns" &>/dev/null; then
    echo "✅ Tekton pipelines are accessible"
else
    echo "❌ Tekton setup may have failed"
fi

echo ""
echo "🎉 Daily dev environment setup complete!"
echo ""
echo "🚀 Next steps:"
echo "1. Add the SSH config above to your ~/.ssh/config"
echo "2. Connect to devcontainer: ssh devcontainer"
echo "3. Test the pipeline: git push origin your-branch"
echo "4. Monitor builds: ssh devcontainer -c 'builds'"
echo ""
echo "💡 Pro tips:"
echo "• Use 'ssh devcontainer -c dev-status' to check environment health"
echo "• Your GitHub webhooks should trigger builds automatically on push"
echo "• AWS tokens are integrated via your company's SAML script"

# Show webhook information if available
webhook_url=$(ssh -i "$keyfile" fedora@$hostname "cat /tmp/webhook-url.txt 2>/dev/null" || echo "")
if [[ ! -z "$webhook_url" ]]; then
    echo ""
    echo "🔗 GitHub Webhook Configuration:"
    echo "   URL: $webhook_url"
    echo "   Go to: https://github.com/kylape/stackrox/settings/hooks"
    echo "   Add webhook with the URL above"
fi