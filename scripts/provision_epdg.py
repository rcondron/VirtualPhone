#!/usr/bin/env python3
"""
ePDG AKA Quintuplet Provisioner.

Generates EAP-AKA quintuplets (RAND, AUTN, RES, CK, IK) from subscriber
credentials in the Open5GS HSS database and writes them to a SQLite database
in the simaka-sql schema for strongSwan's eap-simaka-sql plugin.

Both the ePDG (server) and vphone (client) strongSwan instances share this
database to perform EAP-AKA authentication during IKEv2 tunnel establishment.

Schema (strongSwan simaka-sql):
    quintuplets(id, permanent, rand, autn, ik, ck, res, used)

Usage:
    python3 provision_epdg.py [--count N] [--db-path PATH]
"""

from __future__ import annotations

import logging
import os
import sqlite3
import struct
import sys
import time

# Allow import of euicc.crypto.milenage
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [epdg-provision] %(message)s")
logger = logging.getLogger(__name__)

MONGO_HOST = os.environ.get("MONGO_HOST", "mongodb")
MONGO_PORT = int(os.environ.get("MONGO_PORT", "27017"))
DB_NAME = "open5gs"

# Number of quintuplets to pre-generate per subscriber
DEFAULT_QUINTUPLET_COUNT = int(os.environ.get("QUINTUPLET_COUNT", "50"))

# Output database path
DEFAULT_DB_PATH = os.environ.get("EPDG_DB_PATH", "/var/lib/epdg/aka_quintuplets.db")

SIMAKA_SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS quintuplets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permanent TEXT NOT NULL,
    rand BLOB NOT NULL,
    autn BLOB NOT NULL,
    ik BLOB NOT NULL,
    ck BLOB NOT NULL,
    res BLOB NOT NULL,
    used INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_quintuplets_permanent
    ON quintuplets(permanent);

CREATE INDEX IF NOT EXISTS idx_quintuplets_rand
    ON quintuplets(permanent, rand);
"""


def get_subscribers():
    """Fetch all subscribers from MongoDB."""
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_HOST, MONGO_PORT, serverSelectionTimeoutMS=5000)
        db = client[DB_NAME]
        subscribers = list(db.subscribers.find({}))
        client.close()
        return subscribers
    except Exception as e:
        logger.error("Failed to connect to MongoDB: %s", e)
        return []


def generate_quintuplets(ki: bytes, opc: bytes, imsi: str, count: int, sqn_start: int = 32):
    """
    Generate AKA quintuplets using Milenage.

    Each quintuplet: (permanent_identity, rand, autn, ik, ck, res)
    Column order matches strongSwan simaka-sql schema.
    The permanent identity uses the NAI format expected by strongSwan:
        0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    """
    from euicc.crypto.milenage import Milenage
    mil = Milenage(ki, opc)

    # Build permanent identity (NAI)
    mcc = imsi[:3]
    mnc = imsi[3:5].zfill(3)
    permanent = f"0{imsi}@nai.epc.mnc{mnc}.mcc{mcc}.3gppnetwork.org"

    amf = bytes.fromhex("8000")
    quintuplets = []

    for i in range(count):
        sqn_val = sqn_start + (i * 32)
        sqn = sqn_val.to_bytes(6, "big")

        # Generate random RAND
        rand = os.urandom(16)

        # Compute Milenage vectors
        mac_a = mil.f1(rand, sqn, amf)
        res, ck, ik, ak = mil.f2345(rand)

        # AUTN = (SQN XOR AK) || AMF || MAC-A
        sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
        autn = sqn_xor_ak + amf + mac_a

        quintuplets.append((permanent, rand, autn, ik, ck, res))

    logger.info("Generated %d quintuplets for IMSI %s (NAI: %s)", count, imsi, permanent)
    return quintuplets


def create_database(db_path: str, quintuplets: list):
    """Create the simaka-sql SQLite database with quintuplets."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.executescript(SIMAKA_SQL_SCHEMA)

    # Clear existing quintuplets
    conn.execute("DELETE FROM quintuplets")

    # Insert all quintuplets
    conn.executemany(
        "INSERT INTO quintuplets (permanent, rand, autn, ik, ck, res) VALUES (?, ?, ?, ?, ?, ?)",
        quintuplets,
    )

    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM quintuplets").fetchone()[0]
    conn.close()

    logger.info("Database created at %s with %d quintuplets", db_path, count)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Provision ePDG AKA quintuplets")
    parser.add_argument("--count", type=int, default=DEFAULT_QUINTUPLET_COUNT,
                        help="Number of quintuplets per subscriber")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH,
                        help="Output SQLite database path")
    parser.add_argument("--wait-mongo", action="store_true",
                        help="Wait for MongoDB to be available")
    args = parser.parse_args()

    if args.wait_mongo:
        logger.info("Waiting for MongoDB at %s:%d...", MONGO_HOST, MONGO_PORT)
        for i in range(60):
            subs = get_subscribers()
            if subs:
                break
            time.sleep(2)
        else:
            logger.error("MongoDB not available after 120s")
            sys.exit(1)

    subscribers = get_subscribers()
    if not subscribers:
        logger.warning("No subscribers found in MongoDB. Creating empty database.")
        create_database(args.db_path, [])
        return

    all_quintuplets = []
    for sub in subscribers:
        imsi = sub.get("imsi", "")
        security = sub.get("security", {})
        ki_hex = security.get("k", "")
        op_hex = security.get("op_value", "")
        op_type = security.get("op_type", 0)
        sqn = security.get("sqn", 32)

        if not imsi or not ki_hex or not op_hex:
            logger.warning("Skipping subscriber %s: missing credentials", imsi)
            continue

        ki = bytes.fromhex(ki_hex)

        if op_type == 0:
            # OP provided, compute OPc
            from euicc.crypto.milenage import Milenage
            opc = Milenage(ki, bytes(16)).compute_opc(ki, bytes.fromhex(op_hex))
        else:
            opc = bytes.fromhex(op_hex)

        quints = generate_quintuplets(ki, opc, imsi, args.count, sqn)
        all_quintuplets.extend(quints)

    create_database(args.db_path, all_quintuplets)
    logger.info("Provisioning complete: %d total quintuplets for %d subscribers",
                len(all_quintuplets), len(subscribers))


if __name__ == "__main__":
    main()
