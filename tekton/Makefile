.PHONY: build-image
build-image:
	podman build . | tee /tmp/stackrox-builder-image-tag

.PHONY: push-image
push-image: build-image
	podman tag $(shell tail -n 1 /tmp/stackrox-builder-image-tag) quay.io/klape/stackrox-builder:latest
	podman push --tls-verify=false quay.io/klape/stackrox-builder:latest

.PHONY: push-image-local
push-image-local: build-image
	podman tag $(shell tail -n 1 /tmp/stackrox-builder-image-tag) localhost:5001/stackrox/stackrox-builder:latest
	podman push --tls-verify=false localhost:5001/stackrox/stackrox-builder:latest

.PHONY: build-and-run-local
build-and-run-local: push-image-local
	kubectl delete pr --all
	kubectl create -f resources/pipelinerun.yaml
