#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[vphone-init]"

log() { echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') $*"; }

log "Starting VirtualPhone environment..."

# ---- Networking ----------------------------------------------------------
log "Configuring network namespaces and IPsec..."

# Enable IP forwarding for VoWiFi IPsec tunnels
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Configure IPsec (strongswan) if VoWiFi is enabled
if [ -n "${VPHONE_IMS_PROXY:-}" ]; then
    log "Configuring strongSwan for VoWiFi..."
    envsubst < /opt/vphone/config/ipsec.conf.tmpl > /etc/ipsec.conf 2>/dev/null || true
    envsubst < /opt/vphone/config/ipsec.secrets.tmpl > /etc/ipsec.secrets 2>/dev/null || true
fi

# ---- eUICC Initialization -----------------------------------------------
log "Initializing virtual eUICC (EID: ${VPHONE_EUICC_EID:-not-set})..."

PROFILE_DIR="/var/lib/vphone/profiles"
mkdir -p "$PROFILE_DIR"

# Generate eUICC platform keys if they don't exist
KEY_DIR="/var/lib/vphone/keys"
mkdir -p "$KEY_DIR"

if [ ! -f "$KEY_DIR/euicc_sk.pem" ]; then
    log "Generating eUICC key pair..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/euicc_sk.pem"
    openssl ec -in "$KEY_DIR/euicc_sk.pem" -pubout -out "$KEY_DIR/euicc_pk.pem"
    # Generate self-signed certificate for the eUICC
    openssl req -new -x509 -key "$KEY_DIR/euicc_sk.pem" \
        -out "$KEY_DIR/euicc_cert.pem" -days 3650 \
        -subj "/CN=VirtualeUICC/O=VirtualPhone/OU=eUICC/${VPHONE_EUICC_EID:-00}"
    log "eUICC keys generated."
fi

if [ ! -f "$KEY_DIR/ims_sk.pem" ]; then
    log "Generating IMS/IPsec key pair..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/ims_sk.pem"
    openssl ec -in "$KEY_DIR/ims_sk.pem" -pubout -out "$KEY_DIR/ims_pk.pem"
    log "IMS keys generated."
fi

chown -R vphone:vphone "$KEY_DIR" "$PROFILE_DIR"

# ---- Wait for redroid ----------------------------------------------------
if [ -n "${REDROID_HOST:-}" ]; then
    log "Waiting for redroid ADB at ${REDROID_HOST}:${REDROID_ADB_PORT:-5555}..."
    for i in $(seq 1 30); do
        if socat -T2 TCP:"${REDROID_HOST}:${REDROID_ADB_PORT:-5555}" /dev/null 2>/dev/null; then
            log "redroid is reachable."
            break
        fi
        if [ "$i" -eq 30 ]; then
            log "WARNING: redroid not reachable after 30 attempts. Continuing anyway."
        fi
        sleep 2
    done
fi

# ---- Launch --------------------------------------------------------------
log "Initialization complete. Launching services..."
exec "$@"
