"""
ISD-R (Issuer Security Domain - Root) implementation.

The ISD-R is the root security domain of the eUICC. It:
- Manages the eUICC lifecycle
- Controls ISD-P creation and deletion
- Handles platform-level security (key management, authentication)
- Processes STORE DATA commands from the SM-DP+

Reference: GSMA SGP.22 Section 4, GlobalPlatform Card Specification 2.3
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# GlobalPlatform ISD-R AID
ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")


class ISDRoot:
    """
    Issuer Security Domain - Root.

    The ISD-R is always present on the eUICC and cannot be deleted.
    It has the highest security privilege level and controls all
    other security domains on the card.
    """

    def __init__(self, eid: str, key_dir: str = "/var/lib/vphone/keys"):
        self.eid = eid
        self.key_dir = Path(key_dir)
        self.aid = ISDR_AID

        self._private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._public_key: Optional[ec.EllipticCurvePublicKey] = None
        self._certificate: Optional[bytes] = None

        # Platform key sets for SCP03 (Secure Channel Protocol 03)
        self._key_sets: dict[int, dict[str, bytes]] = {}

        self._initialized = False

    def initialize(self) -> None:
        """Initialize the ISD-R by loading or generating keys."""
        self._load_keys()
        self._init_default_keyset()
        self._initialized = True
        logger.info("ISD-R initialized for EID=%s", self.eid)

    def _load_keys(self) -> None:
        """Load eUICC key pair from disk."""
        sk_path = self.key_dir / "euicc_sk.pem"
        pk_path = self.key_dir / "euicc_pk.pem"
        cert_path = self.key_dir / "euicc_cert.pem"

        if sk_path.exists():
            with open(sk_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            self._public_key = self._private_key.public_key()
            logger.info("Loaded eUICC private key")
        else:
            logger.info("Generating new eUICC key pair")
            self._private_key = ec.generate_private_key(ec.SECP256R1())
            self._public_key = self._private_key.public_key()
            self.key_dir.mkdir(parents=True, exist_ok=True)
            with open(sk_path, "wb") as f:
                f.write(self._private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            with open(pk_path, "wb") as f:
                f.write(self._public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ))

        if cert_path.exists():
            with open(cert_path, "rb") as f:
                self._certificate = f.read()

    def _init_default_keyset(self) -> None:
        """Initialize default SCP03 key set (key version 0x01)."""
        # In a real eUICC, these are provisioned during manufacturing.
        # We derive them from the EID for deterministic behavior.
        seed = self.eid.encode() + b"SCP03_DEFAULT"
        base = hashlib.sha256(seed).digest()

        self._key_sets[0x01] = {
            "enc": base[:16],  # S-ENC key
            "mac": hashlib.sha256(base + b"MAC").digest()[:16],  # S-MAC key
            "dek": hashlib.sha256(base + b"DEK").digest()[:16],  # DEK key
        }

    def get_public_key_bytes(self) -> bytes:
        """Return the eUICC public key in uncompressed point format."""
        if self._public_key is None:
            raise RuntimeError("ISD-R not initialized")
        return self._public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data using the eUICC private key (ECDSA with SHA-256)."""
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.hazmat.primitives.hashes import SHA256

        if self._private_key is None:
            raise RuntimeError("ISD-R not initialized")

        signature = self._private_key.sign(data, ec.ECDSA(SHA256()))
        return signature

    def verify(self, data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify an ECDSA signature."""
        from cryptography.hazmat.primitives.hashes import SHA256

        try:
            public_key.verify(signature, data, ec.ECDSA(SHA256()))
            return True
        except Exception:
            return False

    def get_keyset(self, version: int = 0x01) -> dict[str, bytes]:
        """Return an SCP03 key set."""
        if version not in self._key_sets:
            raise KeyError(f"Key set version {version:#x} not found")
        return self._key_sets[version]

    def get_eid(self) -> str:
        return self.eid

    def get_certificate(self) -> Optional[bytes]:
        return self._certificate

    @property
    def is_initialized(self) -> bool:
        return self._initialized
