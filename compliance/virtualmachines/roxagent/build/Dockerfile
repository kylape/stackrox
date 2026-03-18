# roxagent development image
# Compatible with existing quadlet unit file

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

# Create the expected directory structure (matches main image)
RUN mkdir -p /stackrox/bin

# Copy the roxagent binary
COPY roxagent /stackrox/bin/roxagent

# Set entrypoint
ENTRYPOINT ["/stackrox/bin/roxagent"]

# Default command matches quadlet's Exec=--host-path /host
CMD ["--host-path", "/host"]
