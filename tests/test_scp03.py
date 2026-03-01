"""Tests for SCP03 (Secure Channel Protocol 03)."""

import os
import pytest

from euicc.crypto.scp03 import SCP03, SCP03Session


class TestSCP03:
    @pytest.fixture
    def scp03(self):
        """Create SCP03 instance with test keys."""
        enc_key = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
        mac_key = bytes.fromhex("505152535455565758595a5b5c5d5e5f")
        dek_key = bytes.fromhex("606162636465666768696a6b6c6d6e6f")
        return SCP03(enc_key, mac_key, dek_key)

    def test_initialize_update(self, scp03):
        """Test INITIALIZE UPDATE produces valid outputs."""
        host_challenge = os.urandom(8)
        card_challenge, card_crypto = scp03.initialize_update(host_challenge)

        assert len(card_challenge) == 8
        assert len(card_crypto) == 8
        assert scp03._session is not None

    def test_mutual_authentication(self, scp03):
        """Test full mutual authentication flow."""
        host_challenge = os.urandom(8)
        card_challenge, card_crypto = scp03.initialize_update(host_challenge)

        # Compute host cryptogram (same derivation as card)
        context = host_challenge + card_challenge
        host_crypto = scp03._compute_cryptogram(
            SCP03.DERIVE_HOST_CRYPTO, context, scp03._session.s_mac
        )

        result = scp03.external_authenticate(
            host_crypto, host_challenge, card_challenge
        )
        assert result is True

    def test_bad_host_cryptogram(self, scp03):
        """Test that wrong host cryptogram is rejected."""
        host_challenge = os.urandom(8)
        card_challenge, _ = scp03.initialize_update(host_challenge)

        bad_crypto = b"\x00" * 8
        result = scp03.external_authenticate(
            bad_crypto, host_challenge, card_challenge
        )
        assert result is False
        assert scp03._session is None  # Session should be cleared

    def test_wrap_command(self, scp03):
        """Test command wrapping with MAC."""
        host_challenge = os.urandom(8)
        card_challenge, _ = scp03.initialize_update(host_challenge)

        # Authenticate
        context = host_challenge + card_challenge
        host_crypto = scp03._compute_cryptogram(
            SCP03.DERIVE_HOST_CRYPTO, context, scp03._session.s_mac
        )
        scp03.external_authenticate(host_crypto, host_challenge, card_challenge)

        # Wrap a command
        apdu = bytes([0x80, 0xE2, 0x00, 0x00]) + b"\x01\x02\x03\x04"
        wrapped = scp03.wrap_command(apdu)

        # Wrapped should be longer (encrypted data + MAC)
        assert len(wrapped) > len(apdu)

    def test_session_keys_unique(self, scp03):
        """Test that different host challenges produce different session keys."""
        ch1 = os.urandom(8)
        _, _ = scp03.initialize_update(ch1)
        s1 = (scp03._session.s_enc, scp03._session.s_mac)

        ch2 = os.urandom(8)
        _, _ = scp03.initialize_update(ch2)
        s2 = (scp03._session.s_enc, scp03._session.s_mac)

        assert s1[0] != s2[0]  # Different S-ENC
        assert s1[1] != s2[1]  # Different S-MAC

    def test_padding(self):
        """Test ISO 9797-1 Method 2 padding."""
        data = b"\x01\x02\x03"
        padded = SCP03._pad(data)
        assert padded[3] == 0x80
        assert len(padded) % 16 == 0

        unpadded = SCP03._unpad(padded)
        assert unpadded == data

    def test_cmac(self):
        """Test AES-CMAC computation."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        data = b""
        mac = SCP03._cmac(key, data)
        assert len(mac) == 16
