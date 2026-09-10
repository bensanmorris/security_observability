# =============================================================================
# Stage 1: Proto builder
# Compiles the Tetragon .proto files (pre-fetched into the build context by
# ./fetch-tetragon-src.sh) into Python bindings using grpcio-tools.
# grpcio-tools is NOT carried forward into the runtime image.
# =============================================================================
# PYTHON_VERSION also drives the optional Python bootstrap below (see
# BOOTSTRAP_PYTHON), independent of where UBI_PYTHON_IMAGE points -- so it
# stays a separate arg rather than being folded into UBI_PYTHON_IMAGE.
ARG PYTHON_VERSION=311
# Full image reference -- override to build against a specific UBI major
# version (registry.access.redhat.com/ubi8/python-311:latest) or point at a
# corporate mirror/proxy, possibly a bare RHEL 8/9 image with no Python
# preinstalled (see BOOTSTRAP_PYTHON below) instead of the public Red Hat
# registry's UBI "S2I Python" flavor. CI passes this explicitly per matrix
# entry rather than relying on this default -- see build.yml's `build` job.
ARG UBI_PYTHON_IMAGE=registry.access.redhat.com/ubi9/python-${PYTHON_VERSION}:latest

FROM ${UBI_PYTHON_IMAGE} AS proto-builder

# Re-declared -- top-level ARGs (declared before the first FROM) only apply
# to interpolating a FROM line's image reference itself; a stage's own RUN
# steps need it redeclared here to see it at all.
ARG PYTHON_VERSION=311
ARG TETRAGON_VERSION=v1.7.0
# Leave unset to use whatever index pip is already configured for in the
# base image (e.g. a corporate mirror baked into /etc/pip.conf) instead of
# forcing one here. Only set these if the base image has no such default.
ARG PIP_INDEX_URL=
ARG PIP_TRUSTED_HOST=

USER 0

# Off by default -- the public UBI Python image (UBI_PYTHON_IMAGE's default)
# already ships python/pip, so this is a no-op there. Set BOOTSTRAP_PYTHON=true
# when UBI_PYTHON_IMAGE instead points at a bare RHEL 8/9 image with no Python
# preinstalled (e.g. a corporate registry mirror of plain rhel8/rhel9, rather
# than the ubi8/ubi9 "S2I Python" image flavor). BOOTSTRAP_PYTHON_DEVEL adds
# python<ver>-devel/gcc -- confirmed necessary in practice against a bare
# UBI9 image (no prior packages installed): grpcio/cryptography/etc. all had
# prebuilt wheels on PyPI, but pyjks's own dependency `twofish` does not and
# fails to build ("error: [Errno 2] No such file or directory: 'gcc'")
# without it, so treat BOOTSTRAP_PYTHON_DEVEL=true as the default expectation
# for a from-scratch RHEL base image, not just a fallback to try if something
# else fails.
# Honors PYTHON_VERSION (e.g. "311" -> "3.11") rather than hardcoding 3.11,
# so it stays in sync with whatever version UBI_PYTHON_IMAGE's default is
# built from -- a mismatch here would silently bootstrap the wrong Python
# instead of erroring.
#
# RHEL package naming is genuinely inconsistent across streams, confirmed
# against a real bare ubi8 image: 3.11/3.12 (and everything on RHEL 9) are
# plain packages named with the dot (python3.11), installable directly --
# but the older 3.6/3.8/3.9 module streams on RHEL 8 are packaged *without*
# the dot (python38, needs `dnf module enable python38` first) even though
# the binaries they install are still dotted (/usr/bin/python3.8). `dnf list`
# on the dotted package name first is how the two are told apart, since
# hardcoding either convention breaks the other (recommend PYTHON_VERSION=311
# for a UBI 8 build specifically to avoid this entirely -- it not only sits
# on the newer, non-module-stream side of that split, but also has a longer
# upstream EOL runway than 3.8/3.9). Exact package/module names may still
# need adjusting for your specific corporate base image; verify with a
# throwaway build first.
ARG BOOTSTRAP_PYTHON=false
ARG BOOTSTRAP_PYTHON_DEVEL=false
RUN if [ "$BOOTSTRAP_PYTHON" = "true" ]; then \
        PY_DOTTED=$(echo "$PYTHON_VERSION" | sed -E 's/^([0-9])(.*)$/\1.\2/') && \
        if dnf list "python${PY_DOTTED}" >/dev/null 2>&1; then \
            PKG="python${PY_DOTTED}"; \
        else \
            PKG="python${PYTHON_VERSION}" && (dnf module enable -y "$PKG" || true); \
        fi && \
        dnf install -y "$PKG" "${PKG}-pip" \
            $( [ "$BOOTSTRAP_PYTHON_DEVEL" = "true" ] && echo "${PKG}-devel" gcc ) && \
        ln -sf "/usr/bin/python${PY_DOTTED}" /usr/bin/python && \
        ln -sf "/usr/bin/pip${PY_DOTTED}" /usr/bin/pip && \
        dnf clean all ; \
    fi

WORKDIR /build

# Install the protobuf compiler (grpcio-tools) from your accessible index.
# ${VAR:+...} omits the flag entirely when PIP_INDEX_URL/PIP_TRUSTED_HOST are
# unset, falling back to the base image's own pip configuration.
RUN pip install --no-cache-dir \
    ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
    ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} \
    grpcio-tools==1.60.1 \
    protobuf==4.25.3

# The api/ subtree of the Tetragon repo at TETRAGON_VERSION, fetched into the
# build context ahead of time by ./fetch-tetragon-src.sh (run from build.yml
# in CI, or manually before a local build). Pulling it in via COPY rather
# than `git clone`-ing github.com from inside this RUN step means this image
# build itself never needs outbound network access — required in locked-down
# corporate environments where the clone would otherwise fail.
COPY tetragon-src/api /build/tetragon-src/api

# Compile .proto files into Python bindings.
# --proto_path points at api/v1 (the parent of the tetragon/ package dir) so
# that inter-proto imports like 'import "tetragon/foo.proto"' resolve correctly.
# The well-known google.protobuf types are resolved via the grpcio-tools
# bundled _proto directory.
RUN mkdir -p /build/generated && \
    python -m grpc_tools.protoc \
        --proto_path=/build/tetragon-src/api/v1 \
        --proto_path=$(python -c "import grpc_tools, os; print(os.path.join(os.path.dirname(grpc_tools.__file__), '_proto'))") \
        --python_out=/build/generated \
        --grpc_python_out=/build/generated \
        /build/tetragon-src/api/v1/tetragon/*.proto && \
    touch /build/generated/tetragon/__init__.py && \
    echo "=== Generated files ===" && find /build/generated -type f | sort

# Sanity check — fail the build here rather than at runtime
RUN python -c "import sys; sys.path.insert(0, '/build/generated'); from tetragon import tetragon_pb2, events_pb2, sensors_pb2_grpc; print('Proto generation OK')"

# =============================================================================
# Stage 2: Runtime image
# Only the compiled bindings and application code are copied in.
# No compiler toolchain, no git, no grpcio-tools.
# =============================================================================
FROM ${UBI_PYTHON_IMAGE} AS runtime

# See the proto-builder stage above — leave unset to use the base image's own
# pip configuration (e.g. a corporate mirror baked into /etc/pip.conf).
ARG PIP_INDEX_URL=
ARG PIP_TRUSTED_HOST=
# Re-declare so it's available in this stage (top-level ARGs don't cross stages)
ARG TETRAGON_VERSION=v1.7.0
# Version of the cert-analyzer itself — set from git tag or commit SHA by CI
ARG VERSION=dev
# Re-declared for the same reason as TETRAGON_VERSION above, plus the two
# below -- see the proto-builder stage's BOOTSTRAP_PYTHON comment for what
# these do and when to set them.
ARG PYTHON_VERSION=311
ARG BOOTSTRAP_PYTHON=false
ARG BOOTSTRAP_PYTHON_DEVEL=false

# Stamp both versions into the image as environment variables so cert_analyzer.py
# can read them at runtime via os.getenv()
ENV TETRAGON_BUILD_VERSION=${TETRAGON_VERSION}
ENV CERT_ANALYZER_VERSION=${VERSION}

USER 0

RUN if [ "$BOOTSTRAP_PYTHON" = "true" ]; then \
        PY_DOTTED=$(echo "$PYTHON_VERSION" | sed -E 's/^([0-9])(.*)$/\1.\2/') && \
        if dnf list "python${PY_DOTTED}" >/dev/null 2>&1; then \
            PKG="python${PY_DOTTED}"; \
        else \
            PKG="python${PYTHON_VERSION}" && (dnf module enable -y "$PKG" || true); \
        fi && \
        dnf install -y "$PKG" "${PKG}-pip" \
            $( [ "$BOOTSTRAP_PYTHON_DEVEL" = "true" ] && echo "${PKG}-devel" gcc ) && \
        ln -sf "/usr/bin/python${PY_DOTTED}" /usr/bin/python && \
        ln -sf "/usr/bin/pip${PY_DOTTED}" /usr/bin/pip && \
        dnf clean all ; \
    fi

WORKDIR /app

# Install runtime Python dependencies only
COPY requirements.txt .
RUN pip install --upgrade pip --no-cache-dir \
        ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
        ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} && \
    pip install --no-cache-dir \
        ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} \
        ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} \
        --only-binary=grpcio \
        -r requirements.txt

# Copy application code
COPY cert_analyzer.py ./
COPY agent/ ./agent/

# Copy compiled proto bindings from builder stage (not the compiler)
COPY --from=proto-builder /build/generated/tetragon ./tetragon

# Verify bindings are present and importable
RUN ls -la /app/tetragon/ && \
    test -f /app/tetragon/__init__.py && \
    python -c "from tetragon import tetragon_pb2, events_pb2, sensors_pb2_grpc; print('Runtime import OK')" && \
    python -c "from agent.fips_compliance_checker import check_certificate, system_fips_enabled; print('FIPS checker import OK')"

# Permissions for OpenShift/arbitrary UID compatibility
RUN chown -R 1001:0 /app && \
    chmod -R g=u /app

USER 1001

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090')" || exit 1

ENTRYPOINT ["python", "-u", "cert_analyzer.py"]