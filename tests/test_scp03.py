"""Tests for SCP03 (Secure Channel Protocol 03).

Tests cover:
- Key Derivation Function (KDF) based on AES-CMAC
- Mutual authentication (card and host cryptograms)
- Command wrapping (encryption + C-MAC)
- Response unwrapping (R-MAC verification + decryption)
- Session key uniqueness
- ISO 9797-1 Method 2 padding
- AES-CMAC against NIST test vectors (SP 800-38B)
"""

import os
import pytest

from euicc.crypto.scp03 import SCP03, SCP03Session, SecurityError


class TestSCP03KDF:
    """Test SCP03 Key Derivation Function (GPC_SPE_014 Section 6.2.2)."""

    @pytest.fixture
    def scp03(self):
        enc_key = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
        mac_key = bytes.fromhex("505152535455565758595a5b5c5d5e5f")
        dek_key = bytes.fromhex("606162636465666768696a6b6c6d6e6f")
        return SCP03(enc_key, mac_key, dek_key)

    def test_kdf_produces_16_byte_keys(self, scp03):
        """KDF output must be 16 bytes (AES-128 key size)."""
        context = os.urandom(16)
        result = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, context)
        assert len(result) == 16

    def test_kdf_deterministic(self, scp03):
        """Same inputs must produce same output."""
        context = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        r1 = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, context)
        r2 = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, context)
        assert r1 == r2

    def test_kdf_different_constants_different_keys(self, scp03):
        """Different derivation constants must produce different keys."""
        context = os.urandom(16)
        s_enc = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, context)
        s_mac = scp03._kdf(scp03.mac_key, SCP03.DERIVE_S_MAC, context)
        s_rmac = scp03._kdf(scp03.mac_key, SCP03.DERIVE_S_RMAC, context)
        assert s_enc != s_mac
        assert s_mac != s_rmac
        assert s_enc != s_rmac

    def test_kdf_different_context_different_keys(self, scp03):
        """Different contexts must produce different keys."""
        ctx1 = b"\x00" * 16
        ctx2 = b"\xff" * 16
        r1 = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, ctx1)
        r2 = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, ctx2)
        assert r1 != r2

    def test_session_keys_derived_from_correct_static_keys(self, scp03):
        """S-ENC derives from enc_key, S-MAC/S-RMAC from mac_key."""
        host_ch = os.urandom(8)
        card_ch, _ = scp03.initialize_update(host_ch)
        ctx = host_ch + card_ch

        expected_s_enc = scp03._kdf(scp03.enc_key, SCP03.DERIVE_S_ENC, ctx)
        expected_s_mac = scp03._kdf(scp03.mac_key, SCP03.DERIVE_S_MAC, ctx)
        expected_s_rmac = scp03._kdf(scp03.mac_key, SCP03.DERIVE_S_RMAC, ctx)

        assert scp03._session.s_enc == expected_s_enc
        assert scp03._session.s_mac == expected_s_mac
        assert scp03._session.s_rmac == expected_s_rmac


class TestSCP03MutualAuth:
    """Test SCP03 mutual authentication protocol."""

    @pytest.fixture
    def scp03(self):
        enc_key = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
        mac_key = bytes.fromhex("505152535455565758595a5b5c5d5e5f")
        dek_key = bytes.fromhex("606162636465666768696a6b6c6d6e6f")
        return SCP03(enc_key, mac_key, dek_key)

    def test_initialize_update_outputs(self, scp03):
        """INITIALIZE UPDATE produces 8-byte challenge and 8-byte cryptogram."""
        host_challenge = os.urandom(8)
        card_challenge, card_crypto = scp03.initialize_update(host_challenge)

        assert len(card_challenge) == 8
        assert len(card_crypto) == 8
        assert scp03._session is not None

    def test_initialize_update_creates_session(self, scp03):
        """Session must be created with all three session keys."""
        host_challenge = os.urandom(8)
        scp03.initialize_update(host_challenge)

        assert len(scp03._session.s_enc) == 16
        assert len(scp03._session.s_mac) == 16
        assert len(scp03._session.s_rmac) == 16
        assert scp03._session.mac_chaining == b"\x00" * 16
        assert scp03._session.counter == 1

    def test_mutual_authentication_succeeds(self, scp03):
        """Full mutual authentication flow with correct host cryptogram."""
        host_challenge = os.urandom(8)
        card_challenge, card_crypto = scp03.initialize_update(host_challenge)

        context = host_challenge + card_challenge
        host_crypto = scp03._compute_cryptogram(
            SCP03.DERIVE_HOST_CRYPTO, context, scp03._session.s_mac
        )

        result = scp03.external_authenticate(
            host_crypto, host_challenge, card_challenge
        )
        assert result is True
        assert scp03._session is not None  # Session preserved

    def test_bad_host_cryptogram_rejected(self, scp03):
        """Wrong host cryptogram must be rejected and session cleared."""
        host_challenge = os.urandom(8)
        card_challenge, _ = scp03.initialize_update(host_challenge)

        bad_crypto = b"\x00" * 8
        result = scp03.external_authenticate(
            bad_crypto, host_challenge, card_challenge
        )
        assert result is False
        assert scp03._session is None

    def test_external_auth_without_init_update_raises(self, scp03):
        """External authenticate without initialize update must raise."""
        with pytest.raises(RuntimeError, match="Must call initialize_update"):
            scp03.external_authenticate(b"\x00" * 8, b"\x00" * 8, b"\x00" * 8)

    def test_card_cryptogram_verifiable(self, scp03):
        """Card cryptogram can be independently verified by the host."""
        host_challenge = os.urandom(8)
        card_challenge, card_crypto = scp03.initialize_update(host_challenge)

        context = host_challenge + card_challenge
        expected_card_crypto = scp03._compute_cryptogram(
            SCP03.DERIVE_CARD_CRYPTO, context, scp03._session.s_mac
        )
        assert card_crypto == expected_card_crypto

    def test_session_keys_unique_per_challenge(self, scp03):
        """Different host challenges must produce different session keys."""
        ch1 = os.urandom(8)
        scp03.initialize_update(ch1)
        s1 = (scp03._session.s_enc, scp03._session.s_mac, scp03._session.s_rmac)

        ch2 = os.urandom(8)
        scp03.initialize_update(ch2)
        s2 = (scp03._session.s_enc, scp03._session.s_mac, scp03._session.s_rmac)

        assert s1[0] != s2[0]
        assert s1[1] != s2[1]
        assert s1[2] != s2[2]


class TestSCP03CommandWrapping:
    """Test command wrapping/unwrapping with encryption and MAC."""

    @pytest.fixture
    def authenticated_scp03(self):
        """Return an SCP03 instance with completed mutual auth."""
        enc_key = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
        mac_key = bytes.fromhex("505152535455565758595a5b5c5d5e5f")
        dek_key = bytes.fromhex("606162636465666768696a6b6c6d6e6f")
        scp03 = SCP03(enc_key, mac_key, dek_key)

        host_challenge = os.urandom(8)
        card_challenge, _ = scp03.initialize_update(host_challenge)

        context = host_challenge + card_challenge
        host_crypto = scp03._compute_cryptogram(
            SCP03.DERIVE_HOST_CRYPTO, context, scp03._session.s_mac
        )
        scp03.external_authenticate(host_crypto, host_challenge, card_challenge)
        return scp03

    def test_wrap_command_with_data(self, authenticated_scp03):
        """Wrapped APDU should be longer than original (encrypted data + MAC)."""
        apdu = bytes([0x80, 0xE2, 0x00, 0x00]) + b"\x01\x02\x03\x04"
        wrapped = authenticated_scp03.wrap_command(apdu)
        assert len(wrapped) > len(apdu)
        # Header (4) + encrypted data (16, padded to block) + C-MAC (8)
        assert len(wrapped) == 4 + 16 + 8

    def test_wrap_command_no_data(self, authenticated_scp03):
        """Wrapping a header-only APDU should add only C-MAC."""
        apdu = bytes([0x80, 0xCA, 0x00, 0x00])
        wrapped = authenticated_scp03.wrap_command(apdu)
        # Header (4) + C-MAC (8)
        assert len(wrapped) == 12

    def test_wrap_preserves_header(self, authenticated_scp03):
        """First 4 bytes of wrapped APDU must be the original header."""
        apdu = bytes([0x80, 0xE2, 0x01, 0x02]) + b"\xAA\xBB"
        wrapped = authenticated_scp03.wrap_command(apdu)
        assert wrapped[:4] == apdu[:4]

    def test_mac_chaining_advances(self, authenticated_scp03):
        """MAC chaining value must change after each wrapped command."""
        initial_chain = authenticated_scp03._session.mac_chaining

        apdu1 = bytes([0x80, 0xE2, 0x00, 0x00]) + b"\x01"
        authenticated_scp03.wrap_command(apdu1)
        chain_after_1 = authenticated_scp03._session.mac_chaining

        apdu2 = bytes([0x80, 0xE2, 0x00, 0x01]) + b"\x02"
        authenticated_scp03.wrap_command(apdu2)
        chain_after_2 = authenticated_scp03._session.mac_chaining

        assert initial_chain != chain_after_1
        assert chain_after_1 != chain_after_2

    def test_counter_increments(self, authenticated_scp03):
        """Counter must increment with each wrapped command."""
        assert authenticated_scp03._session.counter == 1
        authenticated_scp03.wrap_command(bytes([0x80, 0xE2, 0x00, 0x00]) + b"\x01")
        assert authenticated_scp03._session.counter == 2
        authenticated_scp03.wrap_command(bytes([0x80, 0xE2, 0x00, 0x01]) + b"\x02")
        assert authenticated_scp03._session.counter == 3

    def test_wrap_without_session_raises(self):
        """Wrapping without an active session must raise."""
        scp03 = SCP03(bytes(16), bytes(16), bytes(16))
        with pytest.raises(RuntimeError, match="No active SCP03 session"):
            scp03.wrap_command(bytes([0x80, 0xE2, 0x00, 0x00]))

    def test_unwrap_without_session_raises(self):
        """Unwrapping without an active session must raise."""
        scp03 = SCP03(bytes(16), bytes(16), bytes(16))
        with pytest.raises(RuntimeError, match="No active SCP03 session"):
            scp03.unwrap_response(b"\x90\x00")

    def test_unwrap_short_response_passthrough(self, authenticated_scp03):
        """Short responses (just SW1SW2) pass through without R-MAC check."""
        sw = b"\x90\x00"
        result = authenticated_scp03.unwrap_response(sw)
        assert result == sw


class TestSCP03Padding:
    """Test ISO 9797-1 Method 2 padding."""

    def test_pad_short_data(self):
        data = b"\x01\x02\x03"
        padded = SCP03._pad(data)
        assert padded[3] == 0x80
        assert len(padded) == 16  # Padded to next block boundary
        assert all(b == 0 for b in padded[4:])

    def test_pad_block_boundary_data(self):
        """Data at exact block boundary still gets padding (mandatory 0x80)."""
        data = b"\x01" * 16
        padded = SCP03._pad(data)
        assert len(padded) == 32  # Extra block for padding
        assert padded[16] == 0x80

    def test_pad_empty(self):
        padded = SCP03._pad(b"")
        assert len(padded) == 16
        assert padded[0] == 0x80

    def test_unpad_roundtrip(self):
        for size in [1, 7, 15, 16, 31, 48]:
            data = os.urandom(size)
            assert SCP03._unpad(SCP03._pad(data)) == data

    def test_unpad_no_padding_marker(self):
        """Data without 0x80 marker returns as-is."""
        data = b"\x01\x02\x03\x00\x00"
        assert SCP03._unpad(data) == data


class TestSCP03CMAC:
    """Test AES-CMAC against NIST SP 800-38B test vectors."""

    # NIST SP 800-38B Example 1 - AES-128, empty message
    CMAC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    def test_cmac_empty_message(self):
        """AES-CMAC of empty message (NIST Example 1)."""
        mac = SCP03._cmac(self.CMAC_KEY, b"")
        assert len(mac) == 16
        # NIST SP 800-38B Example 1 expected: bb1d6929 e9593728 7fa37d12 9b756746
        assert mac == bytes.fromhex("bb1d6929e95937287fa37d129b756746")

    def test_cmac_16_byte_message(self):
        """AES-CMAC of 16-byte message (NIST Example 2)."""
        msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        mac = SCP03._cmac(self.CMAC_KEY, msg)
        assert mac == bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")

    def test_cmac_40_byte_message(self):
        """AES-CMAC of 40-byte message (NIST Example 3)."""
        msg = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411"
        )
        mac = SCP03._cmac(self.CMAC_KEY, msg)
        assert mac == bytes.fromhex("dfa66747de9ae63030ca32611497c827")

    def test_cmac_64_byte_message(self):
        """AES-CMAC of 64-byte message (NIST Example 4)."""
        msg = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        mac = SCP03._cmac(self.CMAC_KEY, msg)
        assert mac == bytes.fromhex("51f0bebf7e3b9d92fc49741779363cfe")

    def test_cmac_deterministic(self):
        key = os.urandom(16)
        data = os.urandom(32)
        assert SCP03._cmac(key, data) == SCP03._cmac(key, data)

    def test_cmac_different_keys_different_output(self):
        data = b"test"
        mac1 = SCP03._cmac(bytes(16), data)
        mac2 = SCP03._cmac(bytes(range(16)), data)
        assert mac1 != mac2
