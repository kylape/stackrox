FROM quay.io/fedora/fedora:43

ARG DEV_MODE=false

RUN dnf install -y postgresql elfutils-libelf libbpf nodejs npm procps-ng
COPY image/rhel/static-bin/* /usr/bin
RUN mkdir -p /stackrox/static-data && save-dir-contents /etc/pki/ca-trust /etc/ssl

COPY bundle/nvd_definitions /nvd_definitions
COPY bundle/k8s_definitions /k8s_definitions
COPY bundle/istio_definitions /istio_definitions
COPY bundle/repo2cpe /repo2cpe
COPY scannerv2/image/scanner/dump/genesis_manifests.json /
COPY bundle/genesis-dump.zip /

COPY data /stackrox-data
COPY image/rhel/docs /stackrox/static-data/docs
COPY bin/* /stackrox
RUN mkdir -p /stackrox/bin && \
    ln -s /stackrox/migrator /stackrox/bin/migrator && \
    ln -s /stackrox/self-checks /usr/local/bin/self-checks

# Conditional UI setup based on DEV_MODE
RUN mkdir -p /ui/openapi
COPY ./image/rhel/docs/api/v1/openapi.json /ui/openapi/v1.json
COPY ./image/rhel/docs/api/v2/openapi.json /ui/openapi/v2.json

RUN if [ "$DEV_MODE" = "true" ]; then \
        echo "Building in development mode - copying UI source files"; \
    else \
        echo "Building in production mode - will copy compiled UI assets"; \
    fi

# Copy UI files conditionally
COPY ./ui /ui-temp
RUN if [ "$DEV_MODE" = "true" ]; then \
        # Development mode: copy source files only
        cp -r /ui-temp/* /ui/ && rm -rf /ui/build; \
    else \
        # Production mode: build UI assets first
        cd /ui-temp && npm ci && npm run build && \
        cp -r build/* /ui/ && \
        cp -r node_modules /ui/ || true; \
    fi && \
    rm -rf /ui-temp
