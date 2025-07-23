#!/bin/bash
# setup-tekton-pipeline.sh - Automated Tekton setup for daily dev environment

set -e

GITHUB_USER="kylape"
GITHUB_REPO="stackrox"
NAMESPACE="stackrox-tekton"

echo "🔧 Setting up Tekton pipeline automation..."

# 1. Install Tekton Pipelines
echo "Installing Tekton Pipelines..."
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
kubectl apply --filename https://storage.googleapis.com/tekton-releases/triggers/latest/release.yaml
kubectl apply --filename https://storage.googleapis.com/tekton-releases/triggers/latest/interceptors.yaml

# Wait for Tekton to be ready
echo "Waiting for Tekton to be ready..."
kubectl wait --for=condition=ready pod -l app=tekton-pipelines-controller -n tekton-pipelines --timeout=300s
kubectl wait --for=condition=ready pod -l app=tekton-triggers-controller -n tekton-triggers --timeout=300s

# 2. Create pipeline namespace
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# 3. Setup RBAC for pipeline
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tekton-pipeline-sa
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tekton-pipeline-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: tekton-pipeline-sa
  namespace: $NAMESPACE
EOF

# 4. Setup MinIO for caching (your existing setup)
echo "Setting up MinIO for pipeline caching..."
kubectl apply -n default -f tekton/resources/minio/

# Wait for MinIO
kubectl wait --for=condition=available deployment/minio -n default --timeout=300s

# 5. Install pipeline resources
echo "Installing StackRox Tekton pipeline..."
kubectl apply -n $NAMESPACE -f tekton/resources/stackrox/

# 6. Setup GitHub webhook listener
echo "Setting up GitHub webhook integration..."

# Create webhook secret (use a random token)
WEBHOOK_SECRET=$(openssl rand -hex 20)
kubectl create secret generic github-webhook-secret \
  --from-literal=secretToken="$WEBHOOK_SECRET" \
  -n $NAMESPACE

# 7. Setup Tekton Triggers for GitHub integration
cat <<EOF | kubectl apply -f -
apiVersion: triggers.tekton.dev/v1beta1
kind: EventListener
metadata:
  name: github-webhook-listener
  namespace: $NAMESPACE
spec:
  serviceAccountName: tekton-pipeline-sa
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
  namespace: $NAMESPACE
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
  namespace: $NAMESPACE  
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
      namespace: $NAMESPACE
    spec:
      serviceAccountName: tekton-pipeline-sa
      pipelineRef:
        name: stackrox
      params:
      - name: repo-url
        value: \$(tt.params.git-repo-url)
      - name: revision  
        value: \$(tt.params.git-revision)
      - name: builder-image
        value: "quay.io/klape/stackrox-builder:latest-arm64"
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
                storage: 40Gi
EOF

# 8. Expose webhook endpoint
echo "Setting up webhook endpoint..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: el-github-webhook-listener
  namespace: $NAMESPACE
spec:
  ports:
  - name: http-listener
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    eventlistener: github-webhook-listener
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tekton-webhook
  namespace: $NAMESPACE
  annotations:
    nginx.ingress.io/rewrite-target: /
spec:
  rules:
  - host: tekton-webhook.$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}').nip.io
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: el-github-webhook-listener
            port:
              number: 8080
EOF

# 9. Setup port forwarding for webhook access
echo "Setting up port forwarding for webhook..."
kubectl port-forward service/el-github-webhook-listener 8080:8080 -n $NAMESPACE &
PORTFORWARD_PID=$!

# Wait a moment for port forward to establish
sleep 5

# 10. Use ngrok or similar for public webhook URL (if available)
if command -v ngrok &> /dev/null; then
    echo "Starting ngrok tunnel for webhook..."
    ngrok http 8080 --log=stdout > /tmp/ngrok.log &
    sleep 5
    WEBHOOK_URL=$(curl -s localhost:4040/api/tunnels | grep -o 'https://[^"]*\.ngrok\.io')
    echo "$WEBHOOK_URL" > /tmp/webhook-url
    echo "🌐 Webhook URL: $WEBHOOK_URL"
    echo "📝 Add this webhook to your GitHub repo:"
    echo "   URL: $WEBHOOK_URL"  
    echo "   Secret: $WEBHOOK_SECRET"
    echo "   Events: Just the push event"
else
    echo "⚠️  ngrok not found. You can setup GitHub webhook manually:"
    echo "   Local URL: http://localhost:8080 (port forwarded)"
    echo "   Secret: $WEBHOOK_SECRET"
fi

# 11. Create helpful management scripts
cat > /tmp/tekton-helpers.sh <<'HELPERS'
#!/bin/bash
# Helper functions for managing your Tekton pipeline

# Show recent pipeline runs
show-builds() {
    kubectl get pipelineruns -n stackrox-tekton --sort-by=.metadata.creationTimestamp
}

# Show build logs
build-logs() {
    local run_name=${1:-$(kubectl get pipelineruns -n stackrox-tekton --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d/ -f2)}
    tkn pipelinerun logs $run_name -n stackrox-tekton -f
}

# Trigger manual build
trigger-build() {
    local branch=${1:-$(git branch --show-current)}
    local commit=${2:-$(git rev-parse HEAD)}
    
    kubectl create -f - <<EOF
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  name: manual-build-$(date +%s)
  namespace: stackrox-tekton
spec:
  serviceAccountName: tekton-pipeline-sa
  pipelineRef:
    name: stackrox
  params:
  - name: repo-url
    value: https://github.com/kylape/stackrox.git
  - name: revision
    value: $commit
  - name: builder-image
    value: "quay.io/klape/stackrox-builder:latest-arm64"
  workspaces:
  - name: shared-data
    volumeClaimTemplate:
      spec:
        accessModes:
        - ReadWriteOnce
        resources:
          requests:
            storage: 40Gi
EOF
}

# Export functions
export -f show-builds build-logs trigger-build
HELPERS

chmod +x /tmp/tekton-helpers.sh
echo "source /tmp/tekton-helpers.sh" >> ~/.bashrc

echo "✅ Tekton pipeline setup complete!"
echo ""
echo "🎯 Next steps:"
echo "1. Add webhook to GitHub repo: https://github.com/$GITHUB_USER/$GITHUB_REPO/settings/hooks"
if [ -f /tmp/webhook-url ]; then
    echo "   URL: $(cat /tmp/webhook-url)"
else
    echo "   URL: http://your-public-ip:8080 (setup ngrok or public access)"
fi
echo "   Secret: $WEBHOOK_SECRET"
echo "   Content type: application/json"
echo "   Events: Just the push event"
echo ""
echo "2. Test with: git push origin your-branch"
echo "3. Monitor with: show-builds"
echo "4. View logs with: build-logs [run-name]"
echo ""
echo "Pipeline will automatically build and deploy on every push!"