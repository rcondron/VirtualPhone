#!/system/bin/sh
# init_ril_shim.sh — Start the VirtualPhone RIL shim inside redroid
#
# This script is mounted into redroid and executed on container start.
# It replaces the stock rild with our custom RIL shim that bridges
# Android's Parcel-based RIL protocol to the vphone TCP bridge.
#
# The shim creates /dev/socket/rild and speaks the native Android
# Parcel wire format, so Android's telephony framework (RILJ)
# connects to it transparently.

set -e

RIL_SHIM=/vendor/bin/hw/ril_shim
BRIDGE_HOST="${RIL_BRIDGE_HOST:-172.28.0.20}"

# Wait for the vphone RIL bridge to be reachable
echo "ril_shim_init: waiting for RIL bridge at ${BRIDGE_HOST}:18000..."
for i in $(seq 1 60); do
    if nc -z "$BRIDGE_HOST" 18000 2>/dev/null; then
        echo "ril_shim_init: bridge reachable"
        break
    fi
    sleep 2
done

# Stop the stock rild if running
stop ril-daemon 2>/dev/null || true
stop vendor.ril-daemon 2>/dev/null || true

# Remove any stale rild socket
rm -f /dev/socket/rild

# Set system properties for telephony
setprop gsm.sim.state READY
setprop gsm.operator.numeric 00101
setprop gsm.operator.alpha "VirtualPhone"
setprop gsm.version.ril-impl "VirtualPhone RIL 1.0"
setprop gsm.nitz.time "$(date +%y/%m/%d,%H:%M:%S+00)"
setprop ro.telephony.default_network 13
setprop persist.radio.multisim.config ssss

# Launch the RIL shim
echo "ril_shim_init: starting ril_shim (bridge=${BRIDGE_HOST})"
exec "$RIL_SHIM" "$BRIDGE_HOST"
