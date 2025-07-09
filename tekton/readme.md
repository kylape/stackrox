# Stackrox Tekton Pipeline

This is a side project to try and just get a tekton pipeline to build StackRox as fast as possible.
I'd also like to try to run a bunch of the test suites in the pipeline as well.

## Prerequisites

* Kind (the only k8s cluster I've tested on)
* Storage driver available on cluster (default storage driver in kind seems to work)
* Tekton installed on cluster
* `tkn` CLI
* Scanner bundle
* go 1.24 tgz
* `mc` CLI

## Install

[Install Tekton](https://tekton.dev/docs/pipelines/install/).

(Optional) Disable affinity assitant if you need to:

```
kubectl patch configmap feature-flags -n tekton-pipelines --type='merge' -p='{"data":{"disable-affinity-assistant":"true"}}'
```

Install required Tekton Tasks:

```
tkn hub install task git-clone
tkn hub install task buildah
kubectl create -f resources/task-fetch-cache.yaml -f resources/task-put-cache.yaml
```

Install MinIO:

```
kubectl create -f resources/pvc-minio.yaml -f resources/deploy-minio.yaml
kubectl expose deploy/minio --port 9000 --name minio
```

(Optional) Populate MinIO with data if you have it:

```
kubectl port-forward svc/minio 9000:9000 &
mc alias set minio http://localhost:9000 minioadmin minioadmin
./create-buckets.sh
```

Create the Pipeline:

```
kubectl create -f resources/pipeline.yaml
```

Then run the pipeline:

```
kubectl create -f resources/pipelinerun.yaml
```
