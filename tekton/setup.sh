#!/bin/bash

set -xe
set -o pipefail

kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
kubectl patch configmap feature-flags -n tekton-pipelines --type='merge' -p='{"data":{"disable-affinity-assistant":"true"}}' # for KinD

kubectl create -f resources/minio
kubectl expose deploy/minio --port 9000 --name minio
sleep 1
kubectl wait --for=condition=Available deploy/minio

kubectl port-forward svc/minio 9000:9000 &
port_forward_pid=$!
sleep 1
mc alias set minio http://localhost:9000 minioadmin minioadmin

for bucket in "go-cache" "go-mod-cache" "npm-cache" "scanner-cache" "scanner-mod-cache"; do
    mc mb minio/$bucket
    if [[ -d "buckets/$bucket" ]]; then
        for f in $(ls "buckets/$bucket"); do
            mc put "./buckets/$bucket/$f" "minio/$bucket/$f"
        done
    fi
done

kill $port_forward_pid

kubectl -n tekton-pipelines wait --for=condition=Available deploy/tekton-pipelines-webhook
tkn hub install task git-clone
tkn hub install task buildah
kubectl create sa admin || true
kubectl create -f resources/stackrox
