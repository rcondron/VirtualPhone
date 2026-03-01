"""Tests for the RSP (Remote SIM Provisioning) components."""

import pytest

from rsp.asn1.rsp_definitions import (
    BoundProfilePackage,
    EUICCInfo1,
    ProfileInstallResult,
    ResultCode,
    encode_eid,
    decode_eid,
)
from rsp.lpa import ActivationCode


class TestActivationCode:
    def test_parse_standard(self):
        """Test parsing a standard activation code."""
        ac = ActivationCode.parse("1$smdp.example.com$ABC123")
        assert ac.smdp_address == "smdp.example.com"
        assert ac.matching_id == "ABC123"

    def test_parse_with_oid(self):
        """Test parsing with optional OID."""
        ac = ActivationCode.parse("1$smdp.example.com$ABC123$1.2.3.4")
        assert ac.smdp_address == "smdp.example.com"
        assert ac.matching_id == "ABC123"
        assert ac.oid == "1.2.3.4"

    def test_parse_no_matching_id(self):
        """Test parsing with no matching ID."""
        ac = ActivationCode.parse("1$smdp.example.com")
        assert ac.smdp_address == "smdp.example.com"
        assert ac.matching_id == ""

    def test_parse_invalid(self):
        """Test that invalid formats raise ValueError."""
        with pytest.raises(ValueError):
            ActivationCode.parse("invalid")

        with pytest.raises(ValueError):
            ActivationCode.parse("2$smdp.example.com$ABC")


class TestEIDEncoding:
    def test_encode_eid(self):
        """Test EID BCD encoding."""
        eid = "89001012012341234000000000000001"
        encoded = encode_eid(eid)
        assert len(encoded) == 16  # 32 digits / 2

    def test_decode_eid(self):
        """Test EID BCD decoding."""
        eid = "89001012012341234000000000000001"
        encoded = encode_eid(eid)
        decoded = decode_eid(encoded)
        assert decoded == eid

    def test_roundtrip(self):
        """Test encode/decode roundtrip."""
        eids = [
            "89001012012341234000000000000001",
            "89049032123456789012345678901234",
        ]
        for eid in eids:
            assert decode_eid(encode_eid(eid)) == eid


class TestRSPDefinitions:
    def test_result_codes(self):
        assert ResultCode.OK == 0
        assert ResultCode.INSUFFICIENT_MEMORY == 2
        assert ResultCode.NOT_FOUND == 4

    def test_euicc_info1(self):
        info = EUICCInfo1()
        assert info.svn == bytes([2, 5, 0])

    def test_profile_install_result(self):
        result = ProfileInstallResult(
            transaction_id="test-txn-123",
            iccid="8901000000000000001",
            result_code=ResultCode.OK,
        )
        assert result.result_code == ResultCode.OK

    def test_bound_profile_package(self):
        bpp = BoundProfilePackage(
            profile_metadata={"iccid": "test", "imsi": "test"},
        )
        assert bpp.profile_metadata is not None
