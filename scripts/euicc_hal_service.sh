#!/system/bin/sh
# euicc_hal_service.sh — Minimal eUICC HAL proxy for redroid
#
# Provides a basic eUICC presence to Android's EuiccManager by
# setting the right system properties. The actual eUICC operations
# (profile download, switch, delete) are handled by the vphone
# management API over HTTP.
#
# This stub makes Android detect an embedded eUICC so the Settings
# app shows the "Add eSIM" option.

set -e

VPHONE_HOST="${VPHONE_API_HOST:-172.28.0.20}"
VPHONE_PORT="${VPHONE_API_PORT:-9000}"

# Signal that an eUICC is present
setprop persist.radio.esim.supported true
setprop gsm.euicc.provisioned 1

# Query the vphone management API for EID
EID=""
for i in $(seq 1 30); do
    EID=$(wget -qO- "http://${VPHONE_HOST}:${VPHONE_PORT}/euicc/info" 2>/dev/null \
        | sed -n 's/.*"eid":"\([^"]*\)".*/\1/p')
    if [ -n "$EID" ]; then
        setprop gsm.euicc.eid "$EID"
        echo "euicc_hal: EID=$EID"
        break
    fi
    sleep 2
done

if [ -z "$EID" ]; then
    echo "euicc_hal: could not fetch EID from vphone API, using default"
    setprop gsm.euicc.eid "89001012012341234000000000000001"
fi

echo "euicc_hal: stub service running"

# Keep alive — Android may check the service periodically
while true; do
    sleep 300
done
