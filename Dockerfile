# CloudHawk Multi-Cloud Security Monitoring Tool
# Production-ready Docker image with all enhanced features

FROM python:3.11-slim as builder

# Set environment variables for build
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV CLOUDHAWK_HOME=/opt/cloudhawk
ENV CLOUDHAWK_PORT=5000
ENV CLOUDHAWK_HOST=0.0.0.0
ENV PATH=$CLOUDHAWK_HOME/bin:$PATH

# Set working directory
WORKDIR $CLOUDHAWK_HOME

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create necessary directories
RUN mkdir -p $CLOUDHAWK_HOME/logs \
             $CLOUDHAWK_HOME/src/detection/models \
             $CLOUDHAWK_HOME/src/alerts \
             $CLOUDHAWK_HOME/tests \
             $CLOUDHAWK_HOME/bin

# Copy application code
COPY src/ $CLOUDHAWK_HOME/src/
COPY tests/ $CLOUDHAWK_HOME/tests/
COPY docs/ $CLOUDHAWK_HOME/docs/
COPY config.yaml $CLOUDHAWK_HOME/
COPY setup.py $CLOUDHAWK_HOME/
COPY run_cloudhawk.py $CLOUDHAWK_HOME/
COPY README.md $CLOUDHAWK_HOME/
COPY LICENSE $CLOUDHAWK_HOME/

# Create CloudHawk user for security
RUN useradd -r -s /bin/false -d $CLOUDHAWK_HOME cloudhawk && \
    chown -R cloudhawk:cloudhawk $CLOUDHAWK_HOME

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Initialize CloudHawk if first run\n\
if [ ! -f "$CLOUDHAWK_HOME/.initialized" ]; then\n\
    echo "Initializing CloudHawk..."\n\
    python -c "import sys; sys.path.insert(0, \"/opt/cloudhawk/src\"); from setup import create_directories; create_directories()"\n\
    touch "$CLOUDHAWK_HOME/.initialized"\n\
fi\n\
\n\
# Start CloudHawk\n\
exec python run_cloudhawk.py "$@"' > $CLOUDHAWK_HOME/bin/cloudhawk-start.sh && \
    chmod +x $CLOUDHAWK_HOME/bin/cloudhawk-start.sh && \
    chown cloudhawk:cloudhawk $CLOUDHAWK_HOME/bin/cloudhawk-start.sh

# Switch to non-root user
USER cloudhawk

# Expose port
EXPOSE $CLOUDHAWK_PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:$CLOUDHAWK_PORT/api/v1/health || exit 1

# Default command
CMD ["/opt/cloudhawk/bin/cloudhawk-start.sh"]

# Labels for metadata
LABEL maintainer="CloudHawk Team"
LABEL version="2.0.0"
LABEL description="Multi-cloud security monitoring tool with ML-based anomaly detection"
LABEL org.opencontainers.image.title="CloudHawk"
LABEL org.opencontainers.image.description="Enterprise-grade cloud security monitoring for AWS, Azure, and GCP"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.vendor="CloudHawk"
LABEL org.opencontainers.image.source="https://github.com/${{ github.repository }}"
LABEL org.opencontainers.image.documentation="https://github.com/${{ github.repository }}/blob/main/README.md"