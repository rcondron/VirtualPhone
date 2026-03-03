#!/usr/bin/env bash
#
# Provision test subscriber in Open5GS HSS (MongoDB).
#
# This script adds the test subscriber matching the eUICC test profile
# so that AKA authentication succeeds end-to-end.
#
# Subscriber credentials must match config/euicc_config.yaml:
#   IMSI:  001010123456789
#   Ki:    000102030405060708090a0b0c0d0e0f
#   OPc:   000102030405060708090a0b0c0d0e0f
#   MSISDN: +10000000001
#
set -euo pipefail

MONGO_HOST="${MONGO_HOST:-mongodb}"
MONGO_PORT="${MONGO_PORT:-27017}"
DB_NAME="open5gs"

# Test subscriber credentials (must match euicc_config.yaml test_profile)
IMSI="001010123456789"
KI="000102030405060708090a0b0c0d0e0f"
OPC="000102030405060708090a0b0c0d0e0f"
MSISDN="10000000001"
APN_DEFAULT="internet"
APN_IMS="ims"

echo "[provision] Waiting for MongoDB at ${MONGO_HOST}:${MONGO_PORT}..."
for i in $(seq 1 30); do
    if mongosh --host "$MONGO_HOST" --port "$MONGO_PORT" --eval "db.runCommand({ping: 1})" "$DB_NAME" >/dev/null 2>&1; then
        echo "[provision] MongoDB is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[provision] ERROR: MongoDB not reachable after 30 attempts."
        exit 1
    fi
    sleep 2
done

echo "[provision] Adding test subscriber: IMSI=${IMSI}"

mongosh --host "$MONGO_HOST" --port "$MONGO_PORT" "$DB_NAME" --eval "
db.subscribers.updateOne(
  { imsi: '${IMSI}' },
  {
    \$set: {
      imsi: '${IMSI}',
      msisdn: ['${MSISDN}'],
      security: {
        k: '${KI}',
        amf: '8000',
        op_type: 2,
        op_value: '${OPC}',
        sqn: NumberLong(32)
      },
      schema_version: 1,
      access_restriction_data: 32,
      subscriber_status: 0,
      network_access_mode: 0,
      ambr: {
        downlink: { value: 1, unit: 3 },
        uplink: { value: 1, unit: 3 }
      },
      slice: [{
        sst: 1,
        default_indicator: true,
        session: [
          {
            name: '${APN_DEFAULT}',
            type: 3,
            qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
            ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
            pcc_rule: []
          },
          {
            name: '${APN_IMS}',
            type: 3,
            qos: { index: 5, arp: { priority_level: 1, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
            ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
            pcc_rule: []
          }
        ]
      }]
    }
  },
  { upsert: true }
);
print('Subscriber provisioned: IMSI=${IMSI}');
print('Subscriber count: ' + db.subscribers.countDocuments());
"

echo "[provision] Done."
