FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# Create non-root user
RUN microdnf install -y shadow-utils &&     useradd -u 65532 -r -g 0 -s /sbin/nologin nonroot &&     microdnf clean all

COPY bin/linux_arm64/main /operator
RUN chmod +x /operator

USER 65532:0

ENTRYPOINT ["/operator"]
