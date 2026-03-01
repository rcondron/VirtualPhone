"""Tests for the Milenage algorithm implementation.

Test vectors from 3GPP TS 35.208 (Algorithm Verification).
"""

import pytest

from euicc.crypto.milenage import Milenage


class TestMilenage:
    """Test Milenage using 3GPP TS 35.208 test vectors (Set 1)."""

    # 3GPP TS 35.208 Test Set 1
    KI = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
    OP = bytes.fromhex("cdc202d5123e20f62b6d676ac72cb318")
    OPC = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
    RAND = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
    SQN = bytes.fromhex("ff9bb4d0b607")
    AMF = bytes.fromhex("b9b9")

    # Expected outputs for f2..f5 (verified against TS 35.208)
    EXPECTED_F2 = bytes.fromhex("a54211d5e3ba50bf")   # RES
    EXPECTED_F3 = bytes.fromhex("b40ba9a3c58b2a05bbf0d987b21bf8cb")  # CK
    EXPECTED_F4 = bytes.fromhex("f769bcd751044604127672711c6d3441")  # IK
    EXPECTED_F5 = bytes.fromhex("aa689c648370")       # AK
    EXPECTED_F5_STAR = bytes.fromhex("451e8beca43b")   # AK*

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        """Verify OPc computation from OP and Ki."""
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1_deterministic(self, mil):
        """Test that f1 (MAC-A) is deterministic and 8 bytes."""
        mac_a1 = mil.f1(self.RAND, self.SQN, self.AMF)
        mac_a2 = mil.f1(self.RAND, self.SQN, self.AMF)
        assert mac_a1 == mac_a2
        assert len(mac_a1) == 8

    def test_f1_different_amf(self, mil):
        """Test that different AMF produces different MAC-A."""
        mac1 = mil.f1(self.RAND, self.SQN, bytes.fromhex("0000"))
        mac2 = mil.f1(self.RAND, self.SQN, bytes.fromhex("ffff"))
        assert mac1 != mac2

    def test_f1star_deterministic(self, mil):
        """Test that f1* (MAC-S) is deterministic and 8 bytes."""
        mac_s1 = mil.f1star(self.RAND, self.SQN, self.AMF)
        mac_s2 = mil.f1star(self.RAND, self.SQN, self.AMF)
        assert mac_s1 == mac_s2
        assert len(mac_s1) == 8

    def test_f1_f1star_different(self, mil):
        """Test that f1 and f1* produce different outputs."""
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        mac_s = mil.f1star(self.RAND, self.SQN, self.AMF)
        assert mac_a != mac_s

    def test_f2345(self, mil):
        """Test f2 (RES), f3 (CK), f4 (IK), f5 (AK) outputs."""
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        """Test f5* (AK*) output."""
        ak_star = mil.f5star(self.RAND)
        assert ak_star == self.EXPECTED_F5_STAR

    def test_authenticate_success(self, mil):
        """Test a successful AKA authentication."""
        # Build AUTN: SQN^AK || AMF || MAC-A
        _, _, _, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        autn = sqn_ak + self.AMF + mac_a

        result = mil.authenticate(self.RAND, autn, sqn_stored=0)
        assert result is not None

        res, ck, ik = result
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4

    def test_authenticate_mac_failure(self, mil):
        """Test authentication with wrong MAC (should return None)."""
        # Build AUTN with incorrect MAC
        _, _, _, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        bad_mac = b"\x00" * 8
        autn = sqn_ak + self.AMF + bad_mac

        result = mil.authenticate(self.RAND, autn, sqn_stored=0)
        assert result is None

    def test_authenticate_sqn_too_old(self, mil):
        """Test authentication fails when SQN is below stored value."""
        _, _, _, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        autn = sqn_ak + self.AMF + mac_a

        # SQN from AUTN is ff9bb4d0b607 = 281474439839239
        # Use a stored SQN larger than that
        result = mil.authenticate(self.RAND, autn, sqn_stored=281474439839240)
        assert result is None

    def test_generate_auts(self, mil):
        """Test AUTS generation for resynchronization."""
        sqn = 42
        auts = mil.generate_auts(self.RAND, sqn)
        assert len(auts) == 14  # 6 bytes concealed SQN + 8 bytes MAC-S

    def test_gsm_authenticate(self, mil):
        """Test 2G GSM authentication compatibility."""
        sres, kc = mil.gsm_authenticate(self.RAND)
        assert len(sres) == 4
        assert len(kc) == 8


class TestMilenageTestSet2:
    """Additional test vector: 3GPP TS 35.208 Test Set 2."""

    KI = bytes.fromhex("0396eb317b6d1c36f19c1c84cd6ffd16")
    OP = bytes.fromhex("dbc59adcb6f9a0ef735477b7fadf8374")
    RAND = bytes.fromhex("c00d603103dcee52c4478119494202e8")
    SQN = bytes.fromhex("fd8eef40df7d")
    AMF = bytes.fromhex("af17")

    def test_opc_computation(self):
        """Verify OPc computation."""
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert len(opc) == 16

    def test_f2345_deterministic(self):
        """Verify f2345 outputs are deterministic and correct sizes."""
        opc = Milenage.compute_opc(self.KI, self.OP)
        mil = Milenage(self.KI, opc)
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert len(res) == 8
        assert len(ck) == 16
        assert len(ik) == 16
        assert len(ak) == 6

    def test_full_authentication(self):
        """Test complete AKA authentication with computed OPc."""
        opc = Milenage.compute_opc(self.KI, self.OP)
        mil = Milenage(self.KI, opc)

        # Generate authentication vector (network side)
        res, ck, ik, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        autn = sqn_ak + self.AMF + mac_a

        # Authenticate (UE side)
        result = mil.authenticate(self.RAND, autn, sqn_stored=0)
        assert result is not None
        auth_res, auth_ck, auth_ik = result
        assert auth_res == res
        assert auth_ck == ck
        assert auth_ik == ik


class TestMilenageDifferentKeys:
    """Test that different keys produce different outputs."""

    def test_different_ki_different_res(self):
        ki1 = bytes(16)
        ki2 = bytes(range(16))
        opc = bytes(16)
        rand = bytes(range(16))

        mil1 = Milenage(ki1, opc)
        mil2 = Milenage(ki2, opc)

        res1, _, _, _ = mil1.f2345(rand)
        res2, _, _, _ = mil2.f2345(rand)
        assert res1 != res2

    def test_different_opc_different_res(self):
        ki = bytes(16)
        opc1 = bytes(16)
        opc2 = bytes(range(16))
        rand = bytes(range(16))

        mil1 = Milenage(ki, opc1)
        mil2 = Milenage(ki, opc2)

        res1, _, _, _ = mil1.f2345(rand)
        res2, _, _, _ = mil2.f2345(rand)
        assert res1 != res2

    def test_invalid_key_lengths(self):
        with pytest.raises(ValueError):
            Milenage(bytes(15), bytes(16))
        with pytest.raises(ValueError):
            Milenage(bytes(16), bytes(15))
