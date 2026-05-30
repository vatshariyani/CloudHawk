# CloudHawk — Multi-Cloud Security Monitoring Tool
# Multi-stage build: builder installs deps, production stage runs the app.

# ── Builder ────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# B1 fix: set WORKDIR before COPY so requirements land in a known place
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Production ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CLOUDHAWK_HOME=/opt/cloudhawk \
    CLOUDHAWK_PORT=5000 \
    CLOUDHAWK_HOST=0.0.0.0 \
    FLASK_DEBUG=0

# B11 fix: FLASK_ENV is deprecated — use FLASK_DEBUG=0 instead
ENV PATH=/opt/cloudhawk/bin:$PATH

WORKDIR /opt/cloudhawk

# B2 fix: apt-get clean BEFORE rm -rf lists (correct order)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# B7 fix: copy only site-packages from builder, not all of /usr/local/bin
COPY --from=builder /usr/local/lib/python3.11/site-packages \
                    /usr/local/lib/python3.11/site-packages

# Create runtime directories before copying app code
RUN mkdir -p /opt/cloudhawk/logs \
             /opt/cloudhawk/src/detection/models \
             /opt/cloudhawk/src/alerts \
             /opt/cloudhawk/tests \
             /opt/cloudhawk/bin

# Copy application code — B6 fix: exclude docs (not needed at runtime)
COPY src/    /opt/cloudhawk/src/
COPY tests/  /opt/cloudhawk/tests/
COPY config/ /opt/cloudhawk/config/
COPY setup.py run_cloudhawk.py README.md LICENSE /opt/cloudhawk/

# Create non-root user
RUN useradd -r -s /bin/false -d /opt/cloudhawk cloudhawk && \
    chown -R cloudhawk:cloudhawk /opt/cloudhawk

# B5 fix: write startup script with a heredoc instead of echo + \n literals
COPY --chown=cloudhawk:cloudhawk deployment/entrypoint.sh /opt/cloudhawk/bin/cloudhawk-start.sh
RUN chmod +x /opt/cloudhawk/bin/cloudhawk-start.sh

USER cloudhawk

# B4 fix: EXPOSE does not expand env vars — hardcode the port number
EXPOSE 5000

# B3 fix: use /health which actually exists in app.py
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Labels before CMD (convention)
LABEL maintainer="CloudHawk Team" \
      version="1.0.0" \
      description="Multi-cloud security monitoring for AWS, Azure, and GCP" \
      org.opencontainers.image.title="CloudHawk" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="CloudHawk" \
      org.opencontainers.image.source="https://github.com/vatshariyani/cloudhawk"

CMD ["/opt/cloudhawk/bin/cloudhawk-start.sh"]
