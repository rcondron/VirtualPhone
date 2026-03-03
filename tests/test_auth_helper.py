"""Tests for the S-CSCF auth helper AKA vector generation.

Tests the core Milenage-based auth vector generation that bridges
the Kamailio S-CSCF and Open5GS HSS for IMS AKA authentication.

Tests cover:
- Auth vector generation (RAND, AUTN, XRES, CK, IK)
- AKA nonce format (base64(RAND || AUTN))
- Response verification (XRES matching)
- AUTN structure (SQN XOR AK || AMF || MAC-A)
- Digest-AKA end-to-end verification (client ↔ server)
"""

import base64
import hashlib
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


class TestDigestAKAVerification:
    """Test end-to-end Digest-AKA flow matching client ↔ S-CSCF auth-helper."""

    KI = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    OPC = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    AMF = bytes.fromhex("8000")
    IMSI = "001010000000001"

    def _server_generate_vector(self, sqn_val: int = 32):
        """Simulate auth-helper generating an auth vector."""
        mil = Milenage(self.KI, self.OPC)
        rand = os.urandom(16)
        sqn = sqn_val.to_bytes(6, "big")
        mac_a = mil.f1(rand, sqn, self.AMF)
        res, ck, ik, ak = mil.f2345(rand)
        sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
        autn = sqn_xor_ak + self.AMF + mac_a
        nonce = base64.b64encode(rand + autn).decode()

        mcc = self.IMSI[:3]
        mnc = self.IMSI[3:5].zfill(3)
        realm = f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"

        return {
            "rand": rand, "autn": autn, "xres": res.hex(),
            "ck": ck.hex(), "ik": ik.hex(), "nonce": nonce,
            "realm": realm, "algorithm": "AKAv1-MD5",
        }

    def _client_compute_response(self, www_authenticate: str, impi: str, ki: bytes, opc: bytes, sqn: int = 0):
        """Simulate the client-side AKA response computation (mirrors ims/registration.py)."""
        # Parse WWW-Authenticate header
        params = {}
        for part in www_authenticate.replace("Digest ", "").split(","):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                params[key.strip()] = val.strip().strip('"')

        nonce = params["nonce"]
        realm = params["realm"]
        qop = params.get("qop", "auth")

        # Decode nonce to get RAND and AUTN
        nonce_bytes = base64.b64decode(nonce)
        rand = nonce_bytes[:16]
        autn = nonce_bytes[16:32]

        # Run Milenage
        mil = Milenage(ki, opc)
        result = mil.authenticate(rand, autn, sqn)
        assert result is not None, "AKA authentication failed"
        res, ck, ik = result

        # Digest password = hex-encoded RES (same as ims/registration.py)
        password = res.hex()
        uri = f"sip:{realm}"
        cnonce = os.urandom(8).hex()
        nc = "00000001"

        ha1 = hashlib.md5(f"{impi}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()

        return {
            "username": impi, "realm": realm, "nonce": nonce,
            "uri": uri, "nc": nc, "cnonce": cnonce,
            "qop": qop, "response": response,
        }

    def test_full_digest_aka_flow(self):
        """End-to-end: server generates challenge, client responds, server verifies."""
        from scripts.scscf_auth_helper import verify_digest_response, _vector_cache

        # Server generates vector
        vector = self._server_generate_vector()
        _vector_cache[self.IMSI] = vector

        # Server builds WWW-Authenticate
        www_auth = (
            f'Digest realm="{vector["realm"]}", '
            f'nonce="{vector["nonce"]}", '
            f'algorithm={vector["algorithm"]}, '
            f'qop="auth"'
        )

        # Client computes Digest response
        impi = f"{self.IMSI}@{vector['realm']}"
        client_resp = self._client_compute_response(www_auth, impi, self.KI, self.OPC)

        # Server verifies
        result = verify_digest_response(
            self.IMSI,
            client_resp["username"], client_resp["realm"],
            client_resp["uri"], client_resp["nc"],
            client_resp["cnonce"], client_resp["qop"],
            client_resp["response"],
        )
        assert result is True

    def test_wrong_res_fails_verification(self):
        """Digest response computed with wrong key should fail verification."""
        from scripts.scscf_auth_helper import verify_digest_response, _vector_cache

        vector = self._server_generate_vector()
        _vector_cache[self.IMSI] = vector

        www_auth = (
            f'Digest realm="{vector["realm"]}", '
            f'nonce="{vector["nonce"]}", '
            f'algorithm={vector["algorithm"]}, '
            f'qop="auth"'
        )

        # Client uses wrong key
        wrong_ki = bytes.fromhex("ff" * 16)
        wrong_opc = bytes.fromhex("ff" * 16)
        # With wrong keys, Milenage.authenticate returns None, so we fabricate a fake response
        result = verify_digest_response(
            self.IMSI,
            f"{self.IMSI}@{vector['realm']}", vector["realm"],
            f"sip:{vector['realm']}", "00000001",
            os.urandom(8).hex(), "auth",
            os.urandom(16).hex(),  # random response — will not match
        )
        assert result is False

    def test_no_cached_vector_fails(self):
        """Verification fails when no vector was generated for the IMSI."""
        from scripts.scscf_auth_helper import verify_digest_response, _vector_cache

        # Clear cache
        _vector_cache.pop("999990000000001", None)

        result = verify_digest_response(
            "999990000000001",
            "user@realm", "realm", "sip:realm",
            "00000001", "abc123", "auth", "deadbeef",
        )
        assert result is False

    def test_verify_without_qop(self):
        """Digest verification works without qop (RFC 2069 compatibility)."""
        from scripts.scscf_auth_helper import verify_digest_response, _vector_cache

        vector = self._server_generate_vector()
        _vector_cache[self.IMSI] = vector

        realm = vector["realm"]
        impi = f"{self.IMSI}@{realm}"
        uri = f"sip:{realm}"
        password = vector["xres"]
        nonce = vector["nonce"]

        ha1 = hashlib.md5(f"{impi}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        result = verify_digest_response(
            self.IMSI, impi, realm, uri, "", "", "", response,
        )
        assert result is True

    def test_challenge_header_format(self):
        """The WWW-Authenticate header has correct format for AKAv1-MD5."""
        vector = self._server_generate_vector()
        www_auth = (
            f'Digest realm="{vector["realm"]}", '
            f'nonce="{vector["nonce"]}", '
            f'algorithm={vector["algorithm"]}, '
            f'qop="auth"'
        )
        assert 'realm="ims.mnc' in www_auth
        assert 'algorithm=AKAv1-MD5' in www_auth
        assert 'qop="auth"' in www_auth
        # Nonce should be valid base64
        nonce = vector["nonce"]
        decoded = base64.b64decode(nonce)
        assert len(decoded) == 32  # RAND (16) + AUTN (16)
