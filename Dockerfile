# CloudHawk Multi-Cloud Security Monitoring Tool
# Production-ready Docker image with all enhanced features

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV CLOUDHAWK_HOME=/opt/cloudhawk
ENV CLOUDHAWK_PORT=5000
ENV CLOUDHAWK_HOST=0.0.0.0

# Set working directory
WORKDIR $CLOUDHAWK_HOME

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p $CLOUDHAWK_HOME/logs \
             $CLOUDHAWK_HOME/src/detection/models \
             $CLOUDHAWK_HOME/src/alerts \
             $CLOUDHAWK_HOME/tests

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

# Switch to non-root user
USER cloudhawk

# Expose port
EXPOSE $CLOUDHAWK_PORT

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:$CLOUDHAWK_PORT/api/v1/health || exit 1

# Default command
CMD ["python", "run_cloudhawk.py"]

# Labels for metadata
LABEL maintainer="CloudHawk Team"
LABEL version="2.0.0"
LABEL description="Multi-cloud security monitoring tool with ML-based anomaly detection"
LABEL org.opencontainers.image.title="CloudHawk"
LABEL org.opencontainers.image.description="Enterprise-grade cloud security monitoring for AWS, Azure, and GCP"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.vendor="CloudHawk"