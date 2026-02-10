FROM registry.access.redhat.com/ubi9/python-311:latest

# Switch to root for installation
USER 0

WORKDIR /app

# Install system dependencies
RUN dnf install -y --setopt=tsflags=nodocs \
    gcc \
    python3-devel \
    && dnf clean all

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY cert_analyzer.py .
COPY tetragon/ tetragon/

# Create non-root user (already exists in UBI, just set permissions)
RUN chown -R 1001:0 /app && \
    chmod -R g=u /app

# Switch to non-root user
USER 1001

# Expose metrics port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090')" || exit 1

# Run application
ENTRYPOINT ["python", "-u", "cert_analyzer.py"]
