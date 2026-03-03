#!/usr/bin/env python3
"""
S-CSCF Authentication Helper for Kamailio.

This sidecar HTTP service generates AKA authentication vectors for the S-CSCF.
It queries subscriber credentials from the Open5GS MongoDB HSS database and
generates RAND, AUTN, and XRES using the Milenage algorithm.

The S-CSCF Kamailio instance calls this service to:
1. Get an AKA challenge (RAND, AUTN) for a 401 response
2. Verify the Digest response from an Authorization header

This replaces the need for a full Diameter Cx interface in the test environment.

Endpoints:
  GET  /auth/vector?imsi=<IMSI>      → JSON {rand, autn, xres, ck, ik, nonce, realm, algorithm}
  GET  /auth/challenge?imsi=<IMSI>   → Plain text WWW-Authenticate header value
  GET  /auth/verify?imsi=...&...     → Plain text "OK" or "FAIL"
  POST /auth/verify                   → JSON {success: bool}
  GET  /health                        → JSON {status: ok}
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format="%(asctime)s [auth-helper] %(message)s")
logger = logging.getLogger(__name__)

# MongoDB connection for Open5GS subscriber data
MONGO_HOST = os.environ.get("MONGO_HOST", "mongodb")
MONGO_PORT = int(os.environ.get("MONGO_PORT", "27017"))
DB_NAME = "open5gs"

# In-memory cache of auth vectors (imsi -> vector)
_vector_cache: dict[str, dict] = {}


def _import_milenage():
    """Import Milenage, handling both installed and dev paths."""
    try:
        from euicc.crypto.milenage import Milenage
        return Milenage
    except ImportError:
        # Fallback: add the project root to sys.path
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)
        from euicc.crypto.milenage import Milenage
        return Milenage


def get_subscriber(imsi: str) -> Optional[dict]:
    """Fetch subscriber data from MongoDB."""
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_HOST, MONGO_PORT, serverSelectionTimeoutMS=3000)
        db = client[DB_NAME]
        sub = db.subscribers.find_one({"imsi": imsi})
        client.close()
        return sub
    except Exception as e:
        logger.error("MongoDB query failed: %s", e)
        return None


def generate_auth_vector(imsi: str) -> Optional[dict]:
    """
    Generate an AKA authentication vector for a subscriber.

    Returns {rand, autn, xres, ck, ik, nonce, realm, algorithm} or None if subscriber not found.
    """
    sub = get_subscriber(imsi)
    if not sub:
        logger.warning("Subscriber not found: %s", imsi)
        return None

    security = sub.get("security", {})
    ki_hex = security.get("k", "")
    op_type = security.get("op_type", 0)  # 0=OP, 2=OPc
    op_hex = security.get("op_value", "")
    amf_hex = security.get("amf", "8000")
    sqn_val = security.get("sqn", 32)

    if not ki_hex or not op_hex:
        logger.error("Missing Ki or OP/OPc for IMSI %s", imsi)
        return None

    ki = bytes.fromhex(ki_hex)
    opc = bytes.fromhex(op_hex)

    Milenage = _import_milenage()

    if op_type == 0:
        # OP provided, need to compute OPc
        mil_temp = Milenage(ki, bytes(16))
        opc = mil_temp.compute_opc(ki, bytes.fromhex(op_hex))
    # op_type == 2 means OPc is already provided

    mil = Milenage(ki, opc)

    # Generate RAND
    rand = os.urandom(16)

    # SQN as 6 bytes
    sqn = sqn_val.to_bytes(6, "big")

    # AMF (Authentication Management Field)
    amf = bytes.fromhex(amf_hex)

    # Generate auth vector
    mac_a = mil.f1(rand, sqn, amf)
    res, ck, ik, ak = mil.f2345(rand)

    # AUTN = (SQN XOR AK) || AMF || MAC-A
    sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
    autn = sqn_xor_ak + amf + mac_a

    # Build nonce for SIP: base64(RAND || AUTN)
    nonce = base64.b64encode(rand + autn).decode()

    # Increment SQN in database
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_HOST, MONGO_PORT, serverSelectionTimeoutMS=3000)
        db = client[DB_NAME]
        db.subscribers.update_one(
            {"imsi": imsi},
            {"$set": {"security.sqn": sqn_val + 32}}
        )
        client.close()
    except Exception as e:
        logger.warning("Failed to update SQN: %s", e)

    vector = {
        "rand": rand.hex(),
        "autn": autn.hex(),
        "xres": res.hex(),
        "ck": ck.hex(),
        "ik": ik.hex(),
        "nonce": nonce,
        "realm": f"ims.mnc{imsi[3:5].zfill(3)}.mcc{imsi[0:3]}.3gppnetwork.org",
        "algorithm": "AKAv1-MD5",
    }

    # Cache for verification
    _vector_cache[imsi] = vector
    logger.info("Generated auth vector for IMSI %s: RAND=%s...", imsi, rand[:4].hex())
    return vector


def verify_response(imsi: str, res_hex: str) -> bool:
    """Verify the raw RES from an Authorization header against the expected XRES."""
    cached = _vector_cache.get(imsi)
    if not cached:
        logger.warning("No cached vector for IMSI %s", imsi)
        return False

    expected = cached.get("xres", "")
    if res_hex.lower() == expected.lower():
        logger.info("Auth verification SUCCESS for IMSI %s", imsi)
        return True

    logger.warning("Auth verification FAILED for IMSI %s: got=%s expected=%s",
                    imsi, res_hex[:8], expected[:8])
    return False


def verify_digest_response(imsi: str, username: str, realm: str, uri: str,
                           nc: str, cnonce: str, qop: str, response: str) -> bool:
    """
    Verify a Digest-AKA response from an Authorization header.

    Computes the expected Digest response using the cached XRES as
    the AKA password (hex-encoded RES), matching the client's computation
    per RFC 3310 / 3GPP TS 33.203.
    """
    cached = _vector_cache.get(imsi)
    if not cached:
        logger.warning("No cached vector for IMSI %s", imsi)
        return False

    # The password for Digest-AKA is the hex-encoded RES
    password = cached["xres"]
    nonce = cached["nonce"]

    # Compute HA1 = MD5(username:realm:password)
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()

    # Compute HA2 = MD5(method:uri) — method is always REGISTER for registration
    ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()

    # Compute expected response
    if qop:
        expected = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
    else:
        expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

    if response.lower() == expected.lower():
        logger.info("Digest-AKA verification SUCCESS for IMSI %s", imsi)
        return True

    logger.warning(
        "Digest-AKA verification FAILED for IMSI %s: got=%s expected=%s",
        imsi, response[:8], expected[:8],
    )
    return False


class AuthHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the auth helper."""

    def log_message(self, format, *args):
        logger.info(format, *args)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._respond_json(200, {"status": "ok"})
            return

        if parsed.path == "/auth/vector":
            imsi = params.get("imsi", [None])[0]
            if not imsi:
                self._respond_json(400, {"error": "Missing imsi parameter"})
                return

            vector = generate_auth_vector(imsi)
            if vector:
                self._respond_json(200, vector)
            else:
                self._respond_json(404, {"error": f"Subscriber {imsi} not found"})
            return

        if parsed.path == "/auth/challenge":
            # Returns plain text WWW-Authenticate header value for Kamailio
            imsi = params.get("imsi", [None])[0]
            if not imsi:
                self._respond_text(400, "Missing imsi parameter")
                return

            vector = generate_auth_vector(imsi)
            if vector:
                www_auth = (
                    f'Digest realm="{vector["realm"]}", '
                    f'nonce="{vector["nonce"]}", '
                    f'algorithm={vector["algorithm"]}, '
                    f'qop="auth"'
                )
                self._respond_text(200, www_auth)
            else:
                self._respond_text(404, f"Subscriber {imsi} not found")
            return

        if parsed.path == "/auth/verify":
            # GET-based Digest verification for Kamailio (returns plain text OK/FAIL)
            imsi = params.get("imsi", [None])[0]
            username = params.get("username", [None])[0]
            realm = params.get("realm", [None])[0]
            uri = params.get("uri", [None])[0]
            nc = params.get("nc", [None])[0]
            cnonce = params.get("cnonce", [None])[0]
            qop = params.get("qop", [None])[0]
            response = params.get("response", [None])[0]

            if not all([imsi, username, response]):
                self._respond_text(400, "Missing required parameters")
                return

            success = verify_digest_response(
                imsi, username, realm or "", uri or "",
                nc or "", cnonce or "", qop or "", response,
            )
            self._respond_text(200, "OK" if success else "FAIL")
            return

        self._respond_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/auth/verify":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._respond_json(400, {"error": "Invalid JSON"})
                return

            imsi = data.get("imsi", "")
            res_hex = data.get("res", "")
            if not imsi or not res_hex:
                self._respond_json(400, {"error": "Missing imsi or res"})
                return

            success = verify_response(imsi, res_hex)
            self._respond_json(200, {"success": success})
            return

        self._respond_json(404, {"error": "Not found"})

    def _respond_json(self, code: int, body: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def _respond_text(self, code: int, text: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(text.encode())


def main():
    port = int(os.environ.get("AUTH_HELPER_PORT", "9080"))
    server = HTTPServer(("0.0.0.0", port), AuthHandler)
    logger.info("Auth helper listening on port %d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
