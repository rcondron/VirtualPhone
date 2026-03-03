# VirtualPhone - Virtual eUICC + redroid Android Emulator
# Multi-stage build for a complete virtual telecom environment

# =============================================================================
# Stage 1: Build dependencies and install package
# =============================================================================
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy project metadata first (better layer caching)
COPY pyproject.toml .

# Copy source packages
COPY euicc/ euicc/
COPY hal/ hal/
COPY ims/ ims/
COPY rsp/ rsp/

# Install the package and all dependencies into /install prefix
RUN pip install --no-cache-dir --prefix=/install .

# =============================================================================
# Stage 2: Runtime image
# =============================================================================
FROM python:3.11-slim

LABEL maintainer="VirtualPhone Project"
LABEL description="Virtual eUICC with redroid Android emulator and full telecom stack"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Networking / IPsec (VoWiFi)
    strongswan \
    strongswan-charon \
    libcharon-extra-plugins \
    # TLS / crypto
    openssl \
    libssl3 \
    # IMS / SIP
    libsofia-sip-ua-glib3 \
    # Docker-in-Docker for redroid
    docker.io \
    # Utilities
    iproute2 \
    iptables \
    dnsutils \
    curl \
    jq \
    procps \
    supervisor \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages and entry point scripts from builder
COPY --from=builder /install /usr/local

# Create application user and directories
RUN useradd -r -s /bin/false -m vphone && \
    mkdir -p /opt/vphone /var/lib/vphone/profiles /var/log/vphone /run/vphone && \
    chown -R vphone:vphone /var/lib/vphone /var/log/vphone /run/vphone

WORKDIR /opt/vphone

# Copy non-Python assets (configs, scripts)
COPY config/ config/
COPY scripts/ scripts/

RUN chmod +x scripts/*.sh

# Copy supervisor configuration
COPY config/supervisord.conf /etc/supervisor/conf.d/vphone.conf

# Expose ports
# 5060/5061 - SIP (IMS)
# 4500/500  - IPsec IKE (VoWiFi)
# 8443      - RSP SM-DP+ callback
# 5555      - ADB (redroid)
# 9000      - eUICC management API
EXPOSE 5060/udp 5061/tcp 4500/udp 500/udp 8443/tcp 5555/tcp 9000/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:9000/health || exit 1

ENTRYPOINT ["/opt/vphone/scripts/entrypoint.sh"]
CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/vphone.conf"]
