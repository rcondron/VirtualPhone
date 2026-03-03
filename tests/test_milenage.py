"""Tests for the Milenage algorithm implementation.

Test vectors from 3GPP TS 35.207 and TS 35.208 (Algorithm Verification).
All expected values are verified against the specification documents.
"""

import pytest

from euicc.crypto.milenage import Milenage


class TestMilenageTestSet1:
    """3GPP TS 35.208 Test Set 1 — full verification of all functions."""

    KI = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
    OP = bytes.fromhex("cdc202d5123e20f62b6d676ac72cb318")
    OPC = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
    RAND = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
    SQN = bytes.fromhex("ff9bb4d0b607")
    AMF = bytes.fromhex("b9b9")

    EXPECTED_F1 = bytes.fromhex("4a9ffac354dfafb3")     # MAC-A
    EXPECTED_F1_STAR = bytes.fromhex("01cfaf9ec4e871e9")  # MAC-S
    EXPECTED_F2 = bytes.fromhex("a54211d5e3ba50bf")      # RES
    EXPECTED_F3 = bytes.fromhex("b40ba9a3c58b2a05bbf0d987b21bf8cb")  # CK
    EXPECTED_F4 = bytes.fromhex("f769bcd751044604127672711c6d3441")  # IK
    EXPECTED_F5 = bytes.fromhex("aa689c648370")          # AK
    EXPECTED_F5_STAR = bytes.fromhex("451e8beca43b")      # AK*

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        """Verify OPc = OP XOR E_K(OP) against known value."""
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1(self, mil):
        """Verify f1 (MAC-A) against TS 35.208 expected value."""
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        assert mac_a == self.EXPECTED_F1
        assert len(mac_a) == 8

    def test_f1star(self, mil):
        """Verify f1* (MAC-S) against TS 35.208 expected value."""
        mac_s = mil.f1star(self.RAND, self.SQN, self.AMF)
        assert mac_s == self.EXPECTED_F1_STAR
        assert len(mac_s) == 8

    def test_f1_f1star_different(self, mil):
        """f1 and f1* must produce different outputs."""
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        mac_s = mil.f1star(self.RAND, self.SQN, self.AMF)
        assert mac_a != mac_s

    def test_f2345(self, mil):
        """Verify f2 (RES), f3 (CK), f4 (IK), f5 (AK) against spec."""
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        """Verify f5* (AK*) against spec."""
        ak_star = mil.f5star(self.RAND)
        assert ak_star == self.EXPECTED_F5_STAR

    def test_authenticate_success(self, mil):
        """Full AKA round-trip: build AUTN, authenticate, verify outputs."""
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

    def test_authenticate_bad_mac_returns_none(self, mil):
        """Authentication must fail (return None) when MAC-A is wrong."""
        _, _, _, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        autn = sqn_ak + self.AMF + b"\x00" * 8

        assert mil.authenticate(self.RAND, autn, sqn_stored=0) is None

    def test_authenticate_sqn_replay_returns_none(self, mil):
        """Authentication must fail when SQN is below stored value."""
        _, _, _, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        autn = sqn_ak + self.AMF + mac_a

        sqn_int = int.from_bytes(self.SQN, "big")
        assert mil.authenticate(self.RAND, autn, sqn_stored=sqn_int + 1) is None

    def test_generate_auts(self, mil):
        """AUTS must be 14 bytes and verifiable."""
        auts = mil.generate_auts(self.RAND, 42)
        assert len(auts) == 14
        # Concealed SQN (6 bytes) + MAC-S (8 bytes)
        concealed_sqn = auts[:6]
        mac_s = auts[6:]
        assert len(concealed_sqn) == 6
        assert len(mac_s) == 8

    def test_gsm_authenticate(self, mil):
        """GSM compatibility: SRES=4 bytes, Kc=8 bytes."""
        sres, kc = mil.gsm_authenticate(self.RAND)
        assert len(sres) == 4
        assert len(kc) == 8


class TestMilenageTestSet2:
    """3GPP TS 35.208 Test Set 2 — full verification."""

    KI = bytes.fromhex("0396eb317b6d1c36f19c1c84cd6ffd16")
    OP = bytes.fromhex("dbc59adcb6f9a0ef735477b7fadf8374")
    OPC = bytes.fromhex("56a5d20b8cd93e9b2fc1e5aacb231c4b")
    RAND = bytes.fromhex("c00d603103dcee52c4478119494202e8")
    SQN = bytes.fromhex("fd8eef40df7d")
    AMF = bytes.fromhex("af17")

    EXPECTED_F1 = bytes.fromhex("d3412c9a7680b6d4")
    EXPECTED_F1_STAR = bytes.fromhex("beabbb7ba2e4fd55")
    EXPECTED_F2 = bytes.fromhex("8f354389ae0669ef")
    EXPECTED_F3 = bytes.fromhex("c962b4ec1eb8ebf217e64b83d30ca0c1")
    EXPECTED_F4 = bytes.fromhex("0a09cf20a341312c6af408989cf89a49")
    EXPECTED_F5 = bytes.fromhex("2b1eca5ee9e5")
    EXPECTED_F5_STAR = bytes.fromhex("f09d7c773067")

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1(self, mil):
        assert mil.f1(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1

    def test_f1star(self, mil):
        assert mil.f1star(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1_STAR

    def test_f2345(self, mil):
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        assert mil.f5star(self.RAND) == self.EXPECTED_F5_STAR

    def test_full_authentication(self, mil):
        """Full AKA round-trip with Test Set 2."""
        res, ck, ik, ak = mil.f2345(self.RAND)
        sqn_ak = Milenage._xor(self.SQN, ak)
        mac_a = mil.f1(self.RAND, self.SQN, self.AMF)
        autn = sqn_ak + self.AMF + mac_a

        result = mil.authenticate(self.RAND, autn, sqn_stored=0)
        assert result is not None
        auth_res, auth_ck, auth_ik = result
        assert auth_res == res
        assert auth_ck == ck
        assert auth_ik == ik


class TestMilenageTestSet3:
    """3GPP TS 35.208 Test Set 3."""

    KI = bytes.fromhex("fec86ba6eb707ed08905757b1bb44b8f")
    OP = bytes.fromhex("dbc59adcb6f9a0ef735477b7fadf8374")
    OPC = bytes.fromhex("1006020f0a478bf6b699f15c062e42b3")
    RAND = bytes.fromhex("9f7c8d021accf4db213ccff0c7f71a6a")
    SQN = bytes.fromhex("9d0277595ffc")
    AMF = bytes.fromhex("725c")

    EXPECTED_F1 = bytes.fromhex("9cabc3e99baf7281")
    EXPECTED_F1_STAR = bytes.fromhex("95814ba2b3044324")
    EXPECTED_F2 = bytes.fromhex("8011c48c0c214ed2")
    EXPECTED_F3 = bytes.fromhex("5dbdbb2954e8f3cde665b046179a5098")
    EXPECTED_F4 = bytes.fromhex("59a92d3b476a0443487055cf88b2307b")
    EXPECTED_F5 = bytes.fromhex("33484dc2136b")
    EXPECTED_F5_STAR = bytes.fromhex("deacdd848cc6")

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1(self, mil):
        assert mil.f1(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1

    def test_f1star(self, mil):
        assert mil.f1star(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1_STAR

    def test_f2345(self, mil):
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        assert mil.f5star(self.RAND) == self.EXPECTED_F5_STAR


class TestMilenageTestSet4:
    """3GPP TS 35.208 Test Set 4."""

    KI = bytes.fromhex("9e5944aea94b81165c82fbf9f32db751")
    OP = bytes.fromhex("223014c5806694c007ca1eeef57f004f")
    OPC = bytes.fromhex("a64a507ae1a2a98bb88eb4210135dc87")
    RAND = bytes.fromhex("ce83dbc54ac0274a157c17f80d017bd6")
    SQN = bytes.fromhex("0b604a81eca8")
    AMF = bytes.fromhex("9e09")

    EXPECTED_F1 = bytes.fromhex("74a58220cba84c49")
    EXPECTED_F1_STAR = bytes.fromhex("ac2cc74a96871837")
    EXPECTED_F2 = bytes.fromhex("f365cd683cd92e96")
    EXPECTED_F3 = bytes.fromhex("e203edb3971574f5a94b0d61b816345d")
    EXPECTED_F4 = bytes.fromhex("0c4524adeac041c4dd830d20854fc46b")
    EXPECTED_F5 = bytes.fromhex("f0b9c08ad02e")
    EXPECTED_F5_STAR = bytes.fromhex("6085a86c6f63")

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1(self, mil):
        assert mil.f1(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1

    def test_f1star(self, mil):
        assert mil.f1star(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1_STAR

    def test_f2345(self, mil):
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        assert mil.f5star(self.RAND) == self.EXPECTED_F5_STAR


class TestMilenageTestSet5:
    """3GPP TS 35.208 Test Set 5."""

    KI = bytes.fromhex("4ab1deb05ca6ceb051fc98e77d027a7c")
    OP = bytes.fromhex("2d16c5cd1fdf6b22383584e3bef2a8d8")
    OPC = bytes.fromhex("cd64404dfc450b7e647cc025c97ba2f7")
    RAND = bytes.fromhex("74b0cd6031a1c8339b2b6ce2b8c4a186")
    SQN = bytes.fromhex("e880a1b580b6")
    AMF = bytes.fromhex("9f07")

    EXPECTED_F1 = bytes.fromhex("1653ed115767b0df")
    EXPECTED_F1_STAR = bytes.fromhex("600017c2fda6d624")
    EXPECTED_F2 = bytes.fromhex("763a94d4c5e896fa")
    EXPECTED_F3 = bytes.fromhex("f6bf83928a6dc2d7b37caae1e2b961a9")
    EXPECTED_F4 = bytes.fromhex("48ee136abd85aab083196522db1a113a")
    EXPECTED_F5 = bytes.fromhex("9196965c0787")
    EXPECTED_F5_STAR = bytes.fromhex("755d431b2e00")

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1(self, mil):
        assert mil.f1(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1

    def test_f1star(self, mil):
        assert mil.f1star(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1_STAR

    def test_f2345(self, mil):
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        assert mil.f5star(self.RAND) == self.EXPECTED_F5_STAR


class TestMilenageTestSet6:
    """3GPP TS 35.208 Test Set 6."""

    KI = bytes.fromhex("6c38a116ac280c454f59332ee35c8c4f")
    OP = bytes.fromhex("1ba00a1a7c6700ac8c3ff3e96ad08725")
    OPC = bytes.fromhex("3803ef5363b947c6aaa225e58fae3934")
    RAND = bytes.fromhex("ee6466bc96202c5a557abbeff8babf63")
    SQN = bytes.fromhex("414b98222181")
    AMF = bytes.fromhex("4464")

    EXPECTED_F1 = bytes.fromhex("078adfb488241a57")
    EXPECTED_F1_STAR = bytes.fromhex("80246b8d0186bcf1")
    EXPECTED_F2 = bytes.fromhex("16c8233f05a0ac28")
    EXPECTED_F3 = bytes.fromhex("3f8c7587fe8e4b233af676aede30ba3b")
    EXPECTED_F4 = bytes.fromhex("a7466cc1e6b2a1337d49d3b66e95d7b4")
    EXPECTED_F5 = bytes.fromhex("45b0f69ab06c")
    EXPECTED_F5_STAR = bytes.fromhex("1f53cd2b1113")

    @pytest.fixture
    def mil(self):
        return Milenage(self.KI, self.OPC)

    def test_opc_computation(self):
        opc = Milenage.compute_opc(self.KI, self.OP)
        assert opc == self.OPC

    def test_f1(self, mil):
        assert mil.f1(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1

    def test_f1star(self, mil):
        assert mil.f1star(self.RAND, self.SQN, self.AMF) == self.EXPECTED_F1_STAR

    def test_f2345(self, mil):
        res, ck, ik, ak = mil.f2345(self.RAND)
        assert res == self.EXPECTED_F2
        assert ck == self.EXPECTED_F3
        assert ik == self.EXPECTED_F4
        assert ak == self.EXPECTED_F5

    def test_f5star(self, mil):
        assert mil.f5star(self.RAND) == self.EXPECTED_F5_STAR


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

    def test_different_rand_different_res(self):
        ki = bytes(16)
        opc = bytes(16)
        mil = Milenage(ki, opc)

        res1, _, _, _ = mil.f2345(bytes(16))
        res2, _, _, _ = mil.f2345(bytes(range(16)))
        assert res1 != res2

    def test_f1_different_amf(self):
        ki = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
        opc = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
        mil = Milenage(ki, opc)
        rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
        sqn = bytes.fromhex("ff9bb4d0b607")

        mac1 = mil.f1(rand, sqn, bytes.fromhex("0000"))
        mac2 = mil.f1(rand, sqn, bytes.fromhex("ffff"))
        assert mac1 != mac2


class TestMilenageEdgeCases:
    """Edge cases and error handling."""

    def test_authenticate_wrong_rand_length(self):
        mil = Milenage(bytes(16), bytes(16))
        with pytest.raises(ValueError):
            mil.authenticate(bytes(15), bytes(16), 0)

    def test_authenticate_wrong_autn_length(self):
        mil = Milenage(bytes(16), bytes(16))
        with pytest.raises(ValueError):
            mil.authenticate(bytes(16), bytes(15), 0)

    def test_generate_auts_sqn_zero(self):
        mil = Milenage(bytes(16), bytes(16))
        auts = mil.generate_auts(bytes(16), 0)
        assert len(auts) == 14

    def test_generate_auts_sqn_max(self):
        """SQN is 48-bit — max value is 2^48 - 1."""
        mil = Milenage(bytes(16), bytes(16))
        auts = mil.generate_auts(bytes(16), (1 << 48) - 1)
        assert len(auts) == 14

    def test_gsm_sres_is_prefix_of_res(self):
        """GSM SRES should be first 4 bytes of RES."""
        ki = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
        opc = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
        rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
        mil = Milenage(ki, opc)
        sres, _ = mil.gsm_authenticate(rand)
        res, _, _, _ = mil.f2345(rand)
        assert sres == res[:4]
