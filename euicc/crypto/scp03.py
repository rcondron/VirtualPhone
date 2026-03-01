"""
Secure Channel Protocol 03 (SCP03) implementation.

SCP03 (GlobalPlatform Card Specification Amendment D) provides:
- Mutual authentication between off-card entity and eUICC
- Command/response encryption (AES-CBC)
- Command/response integrity (CMAC)

Used during RSP profile download to establish a secure channel between
the SM-DP+ and the eUICC ISD-R.

Reference: GlobalPlatform GPC_SPE_014 (SCP03)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC as CryptoCMAC

logger = logging.getLogger(__name__)


@dataclass
class SCP03Session:
    """SCP03 secure session state."""
    s_enc: bytes     # Session encryption key
    s_mac: bytes     # Session MAC key
    s_rmac: bytes    # Session response MAC key
    mac_chaining: bytes = b"\x00" * 16  # MAC chaining value
    counter: int = 1


class SCP03:
    """
    SCP03 secure channel protocol.

    Establishes a secure channel using static keys and generates
    session keys via a key derivation mechanism based on AES-CMAC.
    """

    # Derivation data constants (GPC_SPE_014 Section 6.2.2)
    DERIVE_S_ENC = 0x04
    DERIVE_S_MAC = 0x06
    DERIVE_S_RMAC = 0x07
    DERIVE_CARD_CRYPTO = 0x00
    DERIVE_HOST_CRYPTO = 0x01

    def __init__(self, enc_key: bytes, mac_key: bytes, dek_key: bytes):
        """
        Initialize SCP03 with static key set.

        Args:
            enc_key: Static S-ENC key (16 bytes).
            mac_key: Static S-MAC key (16 bytes).
            dek_key: Data encryption key (16 bytes).
        """
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.dek_key = dek_key
        self._session: Optional[SCP03Session] = None

    def initialize_update(self, host_challenge: bytes) -> tuple[bytes, bytes]:
        """
        Process INITIALIZE UPDATE command.

        Generates card challenge and computes card cryptogram.

        Args:
            host_challenge: 8-byte challenge from the host.

        Returns:
            (card_challenge, card_cryptogram) - both 8 bytes.
        """
        card_challenge = os.urandom(8)

        # Derive session keys
        context = host_challenge + card_challenge
        s_enc = self._kdf(self.enc_key, self.DERIVE_S_ENC, context)
        s_mac = self._kdf(self.mac_key, self.DERIVE_S_MAC, context)
        s_rmac = self._kdf(self.mac_key, self.DERIVE_S_RMAC, context)

        self._session = SCP03Session(
            s_enc=s_enc,
            s_mac=s_mac,
            s_rmac=s_rmac,
        )

        # Compute card cryptogram
        card_crypto = self._compute_cryptogram(
            self.DERIVE_CARD_CRYPTO, context, s_mac
        )

        logger.info("SCP03 INITIALIZE UPDATE processed")
        return card_challenge, card_crypto

    def external_authenticate(
        self, host_cryptogram: bytes, host_challenge: bytes, card_challenge: bytes
    ) -> bool:
        """
        Process EXTERNAL AUTHENTICATE command.

        Verifies the host cryptogram to complete mutual authentication.

        Args:
            host_cryptogram: 8-byte cryptogram from the host.
            host_challenge: Original 8-byte host challenge.
            card_challenge: Card challenge from initialize_update.

        Returns:
            True if authentication succeeds.
        """
        if self._session is None:
            raise RuntimeError("Must call initialize_update first")

        context = host_challenge + card_challenge
        expected = self._compute_cryptogram(
            self.DERIVE_HOST_CRYPTO, context, self._session.s_mac
        )

        if not _constant_time_compare(host_cryptogram, expected):
            logger.warning("SCP03 host cryptogram verification FAILED")
            self._session = None
            return False

        logger.info("SCP03 mutual authentication succeeded")
        return True

    def wrap_command(self, apdu: bytes) -> bytes:
        """
        Wrap an APDU command with SCP03 encryption and MAC.

        Applies C-MAC (and optionally C-ENCRYPTION) to the APDU.
        """
        if self._session is None:
            raise RuntimeError("No active SCP03 session")

        # Encrypt the command data if present
        header = apdu[:4]
        data = apdu[4:] if len(apdu) > 4 else b""

        if data:
            # Pad and encrypt with AES-CBC using session encryption key
            padded = self._pad(data)
            iv = self._generate_icv()
            cipher = AES.new(self._session.s_enc, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(padded)
        else:
            encrypted = b""

        # Compute C-MAC
        mac_input = self._session.mac_chaining + header + encrypted
        c_mac = self._cmac(self._session.s_mac, mac_input)
        self._session.mac_chaining = c_mac

        # Assemble wrapped APDU: header + encrypted_data + C-MAC (8 bytes)
        wrapped = header + encrypted + c_mac[:8]
        self._session.counter += 1

        return wrapped

    def unwrap_response(self, response: bytes) -> bytes:
        """
        Unwrap an SCP03-protected response.

        Verifies R-MAC and decrypts the response data.
        """
        if self._session is None:
            raise RuntimeError("No active SCP03 session")

        if len(response) < 10:
            # No R-MAC present (just SW1SW2)
            return response

        data = response[:-10]
        r_mac = response[-10:-2]
        sw = response[-2:]

        # Verify R-MAC
        mac_input = self._session.mac_chaining + data + sw
        expected_mac = self._cmac(self._session.s_rmac, mac_input)

        if not _constant_time_compare(r_mac, expected_mac[:8]):
            logger.warning("SCP03 R-MAC verification failed")
            raise SecurityError("Response MAC verification failed")

        # Decrypt response data
        if data:
            iv = self._generate_icv()
            cipher = AES.new(self._session.s_enc, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(data)
            return self._unpad(decrypted) + sw
        return sw

    def _kdf(self, key: bytes, derivation_constant: int, context: bytes) -> bytes:
        """
        Key derivation function (KDF) per GPC_SPE_014 Section 6.2.2.

        Uses AES-CMAC with:
        - Label = 11 zero bytes || derivation_constant || separator (0x00)
        - Context = 2-byte length || context data
        """
        # Derivation data: label (12 bytes) + separator + L (2 bytes) + i (1 byte) + context
        label = b"\x00" * 11 + bytes([derivation_constant]) + b"\x00"
        length_bits = (len(key) * 8).to_bytes(2, "big")

        data = label + length_bits + b"\x01" + context
        return self._cmac(key, data)

    def _compute_cryptogram(
        self, derivation_constant: int, context: bytes, key: bytes
    ) -> bytes:
        """Compute authentication cryptogram."""
        derived = self._kdf(key, derivation_constant, context)
        return derived[:8]

    def _generate_icv(self) -> bytes:
        """Generate ICV (Initial Chaining Value) for CBC encryption."""
        counter_block = self._session.counter.to_bytes(16, "big")
        cipher = AES.new(self._session.s_enc, AES.MODE_ECB)
        return cipher.encrypt(counter_block)

    @staticmethod
    def _cmac(key: bytes, data: bytes) -> bytes:
        """Compute AES-CMAC."""
        cobj = CryptoCMAC.new(key, ciphermod=AES)
        cobj.update(data)
        return cobj.digest()

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """ISO 9797-1 Method 2 padding (mandatory 0x80 + zeros to block boundary)."""
        padded = data + b"\x80"
        while len(padded) % 16:
            padded += b"\x00"
        return padded

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Remove ISO 9797-1 Method 2 padding."""
        i = len(data) - 1
        while i >= 0 and data[i] == 0x00:
            i -= 1
        if i >= 0 and data[i] == 0x80:
            return data[:i]
        return data


class SecurityError(Exception):
    pass


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
