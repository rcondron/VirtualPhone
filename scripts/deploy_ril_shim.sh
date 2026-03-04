#!/usr/bin/env bash
# deploy_ril_shim.sh — Push RIL shim to a running redroid via ADB
#
# Usage:
#   ./scripts/deploy_ril_shim.sh [ADB_SERIAL]
#
# This script:
#   1. Builds the RIL shim (if not already built)
#   2. Pushes the binary + init script to redroid via ADB
#   3. Remounts /vendor as read-write (requires root)
#   4. Restarts the telephony stack to pick up the new shim
#
# For docker-compose setups, this is NOT needed — the binary and script
# are bind-mounted directly. Use this for standalone redroid instances.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SHIM_DIR="${PROJECT_ROOT}/ril_shim"
SHIM_BIN="${SHIM_DIR}/ril_shim"
INIT_SCRIPT="${SCRIPT_DIR}/init_ril_shim.sh"

ADB_SERIAL="${1:-}"
ADB_CMD="adb"
if [ -n "$ADB_SERIAL" ]; then
    ADB_CMD="adb -s $ADB_SERIAL"
fi

log() { echo "[deploy_ril_shim] $1"; }

# --- Step 1: Build the shim if needed ---
if [ ! -f "$SHIM_BIN" ]; then
    log "Building RIL shim..."
    make -C "$SHIM_DIR"
fi

# Verify it's a static binary
if ! file "$SHIM_BIN" | grep -q "statically linked"; then
    log "WARNING: $SHIM_BIN does not appear to be statically linked"
    log "It may not work inside the Android container"
fi

# --- Step 2: Wait for ADB connection ---
log "Waiting for ADB device..."
$ADB_CMD wait-for-device

# --- Step 3: Root and remount ---
log "Requesting root access..."
$ADB_CMD root 2>/dev/null || true
sleep 2

log "Remounting /vendor as read-write..."
$ADB_CMD remount 2>/dev/null || {
    # Fallback for containers where remount isn't available
    $ADB_CMD shell "mount -o rw,remount /vendor" 2>/dev/null || true
}

# --- Step 4: Push files ---
log "Pushing RIL shim binary..."
$ADB_CMD push "$SHIM_BIN" /vendor/bin/hw/ril_shim
$ADB_CMD shell chmod 755 /vendor/bin/hw/ril_shim

log "Pushing init script..."
$ADB_CMD push "$INIT_SCRIPT" /vendor/bin/hw/init_ril_shim.sh
$ADB_CMD shell chmod 755 /vendor/bin/hw/init_ril_shim.sh

# --- Step 5: Stop stock rild and start our shim ---
log "Stopping stock rild..."
$ADB_CMD shell "stop ril-daemon 2>/dev/null; stop vendor.ril-daemon 2>/dev/null" || true
$ADB_CMD shell "killall rild 2>/dev/null" || true

# Set bridge host — default to the docker network gateway
BRIDGE_HOST="${RIL_BRIDGE_HOST:-172.28.0.20}"
log "Starting RIL shim (bridge=${BRIDGE_HOST})..."
$ADB_CMD shell "RIL_BRIDGE_HOST=${BRIDGE_HOST} nohup /vendor/bin/hw/init_ril_shim.sh > /dev/null 2>&1 &"

# --- Step 6: Verify ---
sleep 3
if $ADB_CMD shell "ls /dev/socket/rild" 2>/dev/null | grep -q rild; then
    log "SUCCESS: /dev/socket/rild exists — shim is running"
else
    log "WARNING: /dev/socket/rild not found — shim may still be starting"
    log "Check with: adb shell logcat -s ril_shim"
fi

log "Done. Monitor with: adb shell logcat -s ril_shim"
