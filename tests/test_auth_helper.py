"""Tests for the S-CSCF auth helper AKA vector generation.

Tests the core Milenage-based auth vector generation that bridges
the Kamailio S-CSCF and Open5GS HSS for IMS AKA authentication.

Tests cover:
- Auth vector generation (RAND, AUTN, XRES, CK, IK)
- AKA nonce format (base64(RAND || AUTN))
- Response verification (XRES matching)
- AUTN structure (SQN XOR AK || AMF || MAC-A)
"""

import base64
import os
import pytest

from euicc.crypto.milenage import Milenage


class TestAuthVectorGeneration:
    """Test AKA authentication vector generation matching HSS behavior."""

    KI = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    OPC = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    AMF = bytes.fromhex("8000")

    def _generate_vector(self, sqn_val: int = 32):
        """Generate an auth vector like the auth helper would."""
        mil = Milenage(self.KI, self.OPC)
        rand = os.urandom(16)
        sqn = sqn_val.to_bytes(6, "big")

        mac_a = mil.f1(rand, sqn, self.AMF)
        res, ck, ik, ak = mil.f2345(rand)

        sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
        autn = sqn_xor_ak + self.AMF + mac_a

        nonce = base64.b64encode(rand + autn).decode()

        return {
            "rand": rand,
            "autn": autn,
            "xres": res,
            "ck": ck,
            "ik": ik,
            "nonce": nonce,
        }

    def test_vector_field_lengths(self):
        """All auth vector fields have correct lengths."""
        v = self._generate_vector()
        assert len(v["rand"]) == 16
        assert len(v["autn"]) == 16  # 6 + 2 + 8
        assert len(v["xres"]) == 8
        assert len(v["ck"]) == 16
        assert len(v["ik"]) == 16

    def test_autn_structure(self):
        """AUTN = (SQN XOR AK) || AMF || MAC-A."""
        v = self._generate_vector(sqn_val=32)
        autn = v["autn"]
        # First 6 bytes: SQN XOR AK
        # Next 2 bytes: AMF (should be 0x8000)
        assert autn[6:8] == self.AMF
        # Last 8 bytes: MAC-A
        assert len(autn[8:]) == 8

    def test_nonce_format(self):
        """Nonce is valid base64 encoding of RAND || AUTN (32 bytes)."""
        v = self._generate_vector()
        decoded = base64.b64decode(v["nonce"])
        assert len(decoded) == 32
        assert decoded[:16] == v["rand"]
        assert decoded[16:32] == v["autn"]

    def test_ue_can_authenticate_with_vector(self):
        """UE side can authenticate using the generated vector."""
        v = self._generate_vector(sqn_val=32)

        # UE uses same Ki/OPc
        mil_ue = Milenage(self.KI, self.OPC)
        result = mil_ue.authenticate(v["rand"], v["autn"], 0)

        assert result is not None
        res, ck, ik = result
        assert res == v["xres"]
        assert ck == v["ck"]
        assert ik == v["ik"]

    def test_wrong_ki_fails_auth(self):
        """Authentication fails with wrong Ki."""
        v = self._generate_vector()
        wrong_ki = bytes.fromhex("ff" * 16)
        mil_wrong = Milenage(wrong_ki, self.OPC)
        # With wrong Ki, MAC verification in authenticate should fail (returns None)
        result = mil_wrong.authenticate(v["rand"], v["autn"], 0)
        assert result is None

    def test_wrong_opc_fails_auth(self):
        """Authentication fails with wrong OPc."""
        v = self._generate_vector()
        wrong_opc = bytes.fromhex("ff" * 16)
        mil_wrong = Milenage(self.KI, wrong_opc)
        result = mil_wrong.authenticate(v["rand"], v["autn"], 0)
        assert result is None

    def test_xres_verification(self):
        """XRES from network matches RES from UE — the core of AKA."""
        v = self._generate_vector()
        mil_ue = Milenage(self.KI, self.OPC)
        result = mil_ue.authenticate(v["rand"], v["autn"], 0)
        assert result is not None
        res, _, _ = result
        # This is the check the S-CSCF performs
        assert res == v["xres"]

    def test_vectors_are_unique(self):
        """Each call generates unique RAND, so vectors are unique."""
        v1 = self._generate_vector()
        v2 = self._generate_vector()
        assert v1["rand"] != v2["rand"]
        assert v1["autn"] != v2["autn"]
        assert v1["xres"] != v2["xres"]
        assert v1["nonce"] != v2["nonce"]

    def test_sqn_affects_autn(self):
        """Different SQN values produce different AUTN values."""
        mil = Milenage(self.KI, self.OPC)
        rand = os.urandom(16)
        amf = self.AMF

        sqn1 = (32).to_bytes(6, "big")
        sqn2 = (64).to_bytes(6, "big")

        mac_a1 = mil.f1(rand, sqn1, amf)
        mac_a2 = mil.f1(rand, sqn2, amf)
        _, _, _, ak = mil.f2345(rand)

        autn1 = bytes(a ^ b for a, b in zip(sqn1, ak)) + amf + mac_a1
        autn2 = bytes(a ^ b for a, b in zip(sqn2, ak)) + amf + mac_a2

        assert autn1 != autn2

    def test_ck_ik_for_ipsec(self):
        """CK and IK are suitable for IPsec SA key material."""
        v = self._generate_vector()
        # CK and IK should be exactly 16 bytes (128-bit AES keys)
        assert len(v["ck"]) == 16
        assert len(v["ik"]) == 16
        # They should not be all zeros
        assert v["ck"] != bytes(16)
        assert v["ik"] != bytes(16)
