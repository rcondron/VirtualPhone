#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[epdg-init]"
log() { echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') $*"; }

log "Starting ePDG initialization..."

# ---- Generate ePDG certificate if not present --------------------------------
CERT_DIR="/etc/swanctl/x509"
KEY_DIR="/etc/swanctl/private"
CA_DIR="/etc/swanctl/x509ca"

if [ ! -f "$KEY_DIR/epdg.key.pem" ]; then
    log "Generating ePDG CA and server certificate..."

    # Generate self-signed CA
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/ca.key.pem"
    openssl req -new -x509 -key "$KEY_DIR/ca.key.pem" \
        -out "$CA_DIR/ca.cert.pem" -days 3650 \
        -subj "/CN=VirtualPhone ePDG CA/O=VirtualPhone"

    # Generate ePDG server key and certificate
    openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/epdg.key.pem"

    # CSR with SAN extension
    openssl req -new -key "$KEY_DIR/epdg.key.pem" \
        -subj "/CN=epdg.epc.mnc001.mcc001.3gppnetwork.org/O=VirtualPhone" \
        -out /tmp/epdg.csr

    openssl x509 -req -in /tmp/epdg.csr \
        -CA "$CA_DIR/ca.cert.pem" -CAkey "$KEY_DIR/ca.key.pem" \
        -CAcreateserial -days 3650 \
        -extfile <(printf "subjectAltName=DNS:epdg.epc.mnc001.mcc001.3gppnetwork.org,IP:172.28.0.45") \
        -out "$CERT_DIR/epdg.cert.pem"

    # Copy CA cert so clients can verify
    cp "$CA_DIR/ca.cert.pem" /var/lib/epdg/ca.cert.pem

    rm -f /tmp/epdg.csr
    log "ePDG certificates generated."
fi

# ---- Enable IP forwarding for tunnel traffic ---------------------------------
log "Configuring networking..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# NAT for tunnel traffic going to the IMS network
iptables -t nat -A POSTROUTING -s 10.47.0.0/24 -j MASQUERADE 2>/dev/null || true

# ---- Wait for quintuplet database -------------------------------------------
DB_PATH="/var/lib/epdg/aka_quintuplets.db"
log "Waiting for quintuplet database at $DB_PATH..."
for i in $(seq 1 30); do
    if [ -f "$DB_PATH" ]; then
        count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM quintuplets;" 2>/dev/null || echo "0")
        if [ "$count" -gt 0 ]; then
            log "Quintuplet database ready ($count quintuplets)."
            break
        fi
    fi
    if [ "$i" -eq 30 ]; then
        log "WARNING: No quintuplet database found after 30 attempts."
    fi
    sleep 2
done

# ---- Start strongSwan -------------------------------------------------------
log "Starting strongSwan charon..."

# Start charon daemon
exec /usr/sbin/charon-systemd --debug-ike 2 --debug-cfg 2 --debug-eap 2 2>&1 || \
    exec /usr/libexec/ipsec/charon 2>&1 || \
    exec /usr/lib/ipsec/charon 2>&1
