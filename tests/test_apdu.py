"""Tests for the APDU handler."""

import tempfile

import pytest

from euicc.apdu.handler import (
    APDUCommand,
    APDUHandler,
    APDUResponse,
    EF_IMSI,
    EF_ICCID,
    EF_SPN,
    INS,
    SW_OK,
    SW_NOT_FOUND,
    SW_CONDITIONS_NOT_SATISFIED,
)
from euicc.euicc import VirtualEUICC


@pytest.fixture
def euicc_with_profile():
    """Create eUICC with an active profile."""
    with tempfile.TemporaryDirectory() as pd:
        with tempfile.TemporaryDirectory() as kd:
            e = VirtualEUICC(profile_dir=pd, key_dir=kd)
            e.initialize()
            e.install_profile({
                "iccid": "8901000000000000001",
                "imsi": "001010123456789",
                "ki": "000102030405060708090a0b0c0d0e0f",
                "opc": "000102030405060708090a0b0c0d0e0f",
                "spn": "Test",
                "mcc": "001",
                "mnc": "01",
            })
            e.enable_profile("8901000000000000001")
            yield e


class TestAPDUCommand:
    def test_parse_case1(self):
        """Case 1: No data, no Le."""
        cmd = APDUCommand.from_bytes(bytes([0x00, 0xA4, 0x00, 0x00]))
        assert cmd.cla == 0x00
        assert cmd.ins == 0xA4
        assert cmd.data == b""

    def test_parse_case2(self):
        """Case 2: No data, Le present."""
        cmd = APDUCommand.from_bytes(bytes([0x00, 0xB0, 0x00, 0x00, 0x10]))
        assert cmd.le == 16

    def test_parse_case3(self):
        """Case 3: Data present, no Le."""
        cmd = APDUCommand.from_bytes(bytes([0x00, 0xA4, 0x04, 0x00, 0x02, 0x6F, 0x07]))
        assert len(cmd.data) == 2
        assert cmd.data == bytes([0x6F, 0x07])

    def test_parse_too_short(self):
        with pytest.raises(ValueError):
            APDUCommand.from_bytes(bytes([0x00, 0xA4]))


class TestAPDUHandler:
    def test_select_ef(self, euicc_with_profile):
        handler = APDUHandler(euicc_with_profile)

        # SELECT EF_IMSI (6F07)
        apdu = bytes([0x00, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07])
        resp = handler.process(apdu)
        assert resp.is_success

    def test_read_imsi(self, euicc_with_profile):
        handler = APDUHandler(euicc_with_profile)

        # SELECT EF_IMSI
        handler.process(bytes([0x00, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]))

        # READ BINARY
        resp = handler.process(bytes([0x00, 0xB0, 0x00, 0x00, 0x10]))
        assert resp.is_success
        assert len(resp.data) > 0

    def test_read_without_select(self, euicc_with_profile):
        handler = APDUHandler(euicc_with_profile)

        # READ BINARY without prior SELECT should fail
        resp = handler.process(bytes([0x00, 0xB0, 0x00, 0x00, 0x10]))
        assert not resp.is_success

    def test_unsupported_instruction(self, euicc_with_profile):
        handler = APDUHandler(euicc_with_profile)

        # Unsupported INS byte
        resp = handler.process(bytes([0x00, 0xFF, 0x00, 0x00]))
        assert resp.sw1 == 0x6D  # INS not supported


class TestAPDUEncoding:
    def test_encode_imsi(self):
        encoded = APDUHandler._encode_imsi("001010123456789")
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_encode_plmn(self):
        plmn = APDUHandler._encode_plmn("001", "01")
        assert len(plmn) == 3

    def test_encode_bcd(self):
        bcd = APDUHandler._encode_bcd("1234567890")
        assert len(bcd) == 5
