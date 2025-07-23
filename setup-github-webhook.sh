#!/bin/bash
# setup-github-webhook.sh - Automatically configure GitHub webhook
# Integrated with your existing workflow patterns

set -e

GITHUB_USER="${GITHUB_USER:-kylape}"
GITHUB_REPO="${GITHUB_REPO:-stackrox}"
WEBHOOK_URL="$1"
WEBHOOK_SECRET="$2"

if [ -z "$WEBHOOK_URL" ] || [ -z "$WEBHOOK_SECRET" ]; then
    echo "Usage: $0 <webhook-url> <webhook-secret>"
    echo "Example: $0 https://abc123.ngrok.io mysecrettoken"
    echo ""
    echo "Environment variables:"
    echo "  GITHUB_USER  - GitHub username (default: kylape)"
    echo "  GITHUB_REPO  - Repository name (default: stackrox)"
    echo "  GITHUB_TOKEN - GitHub personal access token (required)"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN environment variable not set"
    echo "Create a token at: https://github.com/settings/tokens"
    echo "Required scopes: repo, admin:repo_hook"
    exit 1
fi

echo "🔗 Setting up GitHub webhook for $GITHUB_USER/$GITHUB_REPO..."

# Check if webhook already exists
EXISTING_HOOKS=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO/hooks" | \
    jq -r --arg url "$WEBHOOK_URL" '.[] | select(.config.url == $url) | .id')

if [ ! -z "$EXISTING_HOOKS" ]; then
    echo "🗑️  Removing existing webhook..."
    echo "$EXISTING_HOOKS" | while read -r hook_id; do
        curl -s -X DELETE -H "Authorization: token $GITHUB_TOKEN" \
            "https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO/hooks/$hook_id"
    done
fi

# Create new webhook
echo "➕ Creating new webhook..."
WEBHOOK_RESPONSE=$(curl -s -X POST \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Content-Type: application/json" \
    "https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO/hooks" \
    -d '{
        "name": "web",
        "active": true,
        "events": ["push"],
        "config": {
            "url": "'"$WEBHOOK_URL"'",
            "content_type": "json",
            "secret": "'"$WEBHOOK_SECRET"'",
            "insecure_ssl": "0"
        }
    }')

# Check if webhook creation was successful
WEBHOOK_ID=$(echo "$WEBHOOK_RESPONSE" | jq -r '.id // empty')

if [ ! -z "$WEBHOOK_ID" ] && [ "$WEBHOOK_ID" != "null" ]; then
    echo "✅ GitHub webhook created successfully!"
    echo "   Webhook ID: $WEBHOOK_ID"
    echo "   URL: $WEBHOOK_URL"
    echo "   Events: push"
    echo ""
    echo "🧪 Test the webhook with:"
    echo "   git push origin your-branch"
else
    echo "❌ Failed to create webhook"
    echo "Response: $WEBHOOK_RESPONSE"
    exit 1
fi