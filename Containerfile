# =============================================================================
# Stage 1: Proto builder
# Fetches Tetragon .proto files for a given release tag and compiles them
# into Python bindings using grpcio-tools.
# grpcio-tools and git are NOT carried forward into the runtime image.
# =============================================================================
ARG UBI_VERSION=9
ARG PYTHON_VERSION=311

FROM registry.access.redhat.com/ubi${UBI_VERSION}/python-${PYTHON_VERSION}:latest AS proto-builder

ARG TETRAGON_VERSION=v1.1.0
ARG PIP_INDEX_URL=https://pypi.org/simple/
ARG PIP_TRUSTED_HOST=pypi.org

USER 0

WORKDIR /build

# git is needed to fetch the Tetragon source tree at the specified tag
RUN dnf install -y --setopt=tsflags=nodocs git && dnf clean all

# Install the protobuf compiler (grpcio-tools) from your accessible index
RUN pip install --no-cache-dir \
    --index-url ${PIP_INDEX_URL} \
    --trusted-host ${PIP_TRUSTED_HOST} \
    grpcio-tools==1.60.1 \
    protobuf==4.25.3

# Display Tetragon structure
RUN echo "=== Tetragon repo structure ===" && \
    find /build/tetragon-src/api -type f | sort

# Fetch only the api/ subtree of the Tetragon repo at the requested tag —
# a sparse checkout avoids pulling the entire repo history
RUN git clone --depth 1 --branch ${TETRAGON_VERSION} \
    --filter=blob:none --sparse \
    https://github.com/cilium/tetragon.git /build/tetragon-src && \
    cd /build/tetragon-src && \
    git sparse-checkout set api

# Compile .proto files into Python bindings
RUN mkdir -p /build/tetragon && \
    python -m grpc_tools.protoc \
        --proto_path=/build/tetragon-src/api/v1 \
        --python_out=/build/tetragon \
        --grpc_python_out=/build/tetragon \
        /build/tetragon-src/api/v1/tetragon/*.proto \
        /build/tetragon-src/api/v1/*.proto && \
    touch /build/tetragon/__init__.py

# Sanity check — fail the build here rather than at runtime
RUN python -c "import sys; sys.path.insert(0, '/build'); from tetragon import tetragon_pb2, events_pb2, sensors_pb2_grpc; print('Proto generation OK')"

# =============================================================================
# Stage 2: Runtime image
# Only the compiled bindings and application code are copied in.
# No compiler toolchain, no git, no grpcio-tools.
# =============================================================================
FROM registry.access.redhat.com/ubi${UBI_VERSION}/python-${PYTHON_VERSION}:latest AS runtime

ARG PIP_INDEX_URL=https://pypi.org/simple/
ARG PIP_TRUSTED_HOST=pypi.org

USER 0

WORKDIR /app

# Install runtime Python dependencies only
COPY requirements.txt .
RUN pip install --upgrade pip --no-cache-dir \
        --index-url ${PIP_INDEX_URL} \
        --trusted-host ${PIP_TRUSTED_HOST} && \
    pip install --no-cache-dir \
        --index-url ${PIP_INDEX_URL} \
        --trusted-host ${PIP_TRUSTED_HOST} \
        --only-binary=grpcio \
        -r requirements.txt

# Copy application code
COPY cert_analyzer.py .

# Copy compiled proto bindings from builder stage (not the compiler)
COPY --from=proto-builder /build/tetragon ./tetragon

# Verify bindings are present and importable
RUN ls -la /app/tetragon/ && \
    test -f /app/tetragon/__init__.py && \
    python -c "from tetragon import tetragon_pb2, events_pb2, sensors_pb2_grpc; print('Runtime import OK')"

# Permissions for OpenShift/arbitrary UID compatibility
RUN chown -R 1001:0 /app && \
    chmod -R g=u /app

USER 1001

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090')" || exit 1

ENTRYPOINT ["python", "-u", "cert_analyzer.py"]
