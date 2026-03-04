#!/system/bin/sh
# init_ril_shim.sh — Start the VirtualPhone RIL shim inside redroid
#
# This script runs inside the Android container (redroid). It can be:
#   1. Docker-mounted: via docker-compose volumes (preferred)
#   2. ADB-pushed: via scripts/deploy_ril_shim.sh for standalone setups
#
# It replaces the stock rild with our custom RIL shim that bridges
# Android's Parcel-based RIL protocol to the vphone TCP bridge.
#
# The shim creates /dev/socket/rild and speaks the native Android
# Parcel wire format, so Android's telephony framework (RILJ)
# connects to it transparently.

set -e

RIL_SHIM=/vendor/bin/hw/ril_shim
BRIDGE_HOST="${RIL_BRIDGE_HOST:-172.28.0.20}"

log() {
    echo "ril_shim_init: $1"
}

# --- Validate that the shim binary exists and is executable ---
if [ ! -f "$RIL_SHIM" ]; then
    log "ERROR: RIL shim binary not found at $RIL_SHIM"
    log "Push it via: adb push ril_shim /vendor/bin/hw/ril_shim"
    exit 1
fi

if [ ! -x "$RIL_SHIM" ]; then
    log "Setting executable permission on $RIL_SHIM"
    chmod 755 "$RIL_SHIM"
fi

# --- Wait for the vphone RIL bridge to be reachable ---
log "waiting for RIL bridge at ${BRIDGE_HOST}:18000..."
BRIDGE_READY=0
for i in $(seq 1 60); do
    # Try nc first (busybox), fall back to /dev/tcp via shell
    if nc -z "$BRIDGE_HOST" 18000 2>/dev/null; then
        BRIDGE_READY=1
        break
    elif (echo > /dev/tcp/"$BRIDGE_HOST"/18000) 2>/dev/null; then
        BRIDGE_READY=1
        break
    fi
    sleep 2
done

if [ "$BRIDGE_READY" = "0" ]; then
    log "WARNING: bridge not reachable after 120s, starting anyway (shim has own retry)"
fi
log "bridge reachable"

# --- Stop the stock rild if running ---
stop ril-daemon 2>/dev/null || true
stop vendor.ril-daemon 2>/dev/null || true
# Also kill any lingering rild processes
killall rild 2>/dev/null || true

# --- Remove any stale rild socket ---
rm -f /dev/socket/rild

# --- Set system properties for telephony ---
# Note: ro.* properties are read-only after boot. They must be passed as
# kernel command-line args (androidboot.*) in docker-compose. We set them
# here with setprop as a fallback, but only ro.telephony.default_network
# is critical and it's already set via command-line in docker-compose.yml.
setprop gsm.sim.state READY
setprop gsm.operator.numeric 00101
setprop gsm.operator.alpha "VirtualPhone"
setprop gsm.version.ril-impl "VirtualPhone RIL 1.0"
setprop gsm.nitz.time "$(date +%y/%m/%d,%H:%M:%S+00)"
setprop persist.radio.multisim.config ssss

# These may fail silently if already set as ro.* via boot params
setprop ro.telephony.default_network 13 2>/dev/null || true
setprop ro.radio.noril no 2>/dev/null || true

# IMS / VoLTE properties
setprop persist.dbg.volte_avail_ovr 1
setprop persist.dbg.vt_avail_ovr 1
setprop persist.dbg.wfc_avail_ovr 1
setprop persist.radio.calls.on.ims 1

# Verify critical properties took effect
SIM_STATE=$(getprop gsm.sim.state 2>/dev/null)
if [ "$SIM_STATE" != "READY" ]; then
    log "WARNING: gsm.sim.state not set (got: $SIM_STATE)"
fi

# --- Launch the RIL shim ---
log "starting ril_shim (bridge=${BRIDGE_HOST})"
exec "$RIL_SHIM" "$BRIDGE_HOST"
