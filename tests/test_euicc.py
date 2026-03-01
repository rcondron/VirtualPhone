"""Tests for the virtual eUICC core."""

import json
import os
import tempfile

import pytest

from euicc.euicc import VirtualEUICC, EUICCState
from euicc.isdp import ISDP, ProfileState


@pytest.fixture
def tmp_dirs():
    """Create temporary directories for profiles and keys."""
    with tempfile.TemporaryDirectory() as profile_dir:
        with tempfile.TemporaryDirectory() as key_dir:
            yield profile_dir, key_dir


@pytest.fixture
def euicc(tmp_dirs):
    """Create and initialize a VirtualEUICC."""
    profile_dir, key_dir = tmp_dirs
    e = VirtualEUICC(
        eid="89001012012341234000000000000001",
        profile_dir=profile_dir,
        key_dir=key_dir,
    )
    e.initialize()
    return e


@pytest.fixture
def sample_profile():
    """A sample eSIM profile data dict."""
    return {
        "iccid": "8901000000000000001",
        "imsi": "001010123456789",
        "ki": "000102030405060708090a0b0c0d0e0f",
        "opc": "111102030405060708090a0b0c0d0e0f",
        "mcc": "001",
        "mnc": "01",
        "spn": "Test Operator",
        "msisdn": "+10000000001",
    }


class TestEUICCInitialization:
    def test_initialize(self, euicc):
        assert euicc.state == EUICCState.READY
        assert euicc.eid == "89001012012341234000000000000001"

    def test_euicc_info(self, euicc):
        info = euicc.get_euicc_info()
        assert info["eid"] == "89001012012341234000000000000001"
        assert info["state"] == "ready"
        assert info["installed_profiles"] == 0

    def test_no_active_profile_initially(self, euicc):
        assert euicc.get_active_profile() is None

    def test_empty_profile_list(self, euicc):
        profiles = euicc.list_profiles()
        assert profiles == []


class TestProfileManagement:
    def test_install_profile(self, euicc, sample_profile):
        isdp = euicc.install_profile(sample_profile)
        assert isdp.iccid == "8901000000000000001"
        assert isdp.imsi == "001010123456789"
        assert isdp.state == ProfileState.DISABLED

    def test_list_profiles(self, euicc, sample_profile):
        euicc.install_profile(sample_profile)
        profiles = euicc.list_profiles()
        assert len(profiles) == 1
        assert profiles[0]["iccid"] == "8901000000000000001"

    def test_enable_profile(self, euicc, sample_profile):
        euicc.install_profile(sample_profile)
        euicc.enable_profile("8901000000000000001")
        active = euicc.get_active_profile()
        assert active is not None
        assert active.iccid == "8901000000000000001"
        assert active.state == ProfileState.ENABLED

    def test_disable_profile(self, euicc, sample_profile):
        euicc.install_profile(sample_profile)
        euicc.enable_profile("8901000000000000001")
        euicc.disable_profile("8901000000000000001")
        assert euicc.get_active_profile() is None

    def test_delete_profile(self, euicc, sample_profile):
        euicc.install_profile(sample_profile)
        euicc.delete_profile("8901000000000000001")
        assert len(euicc.list_profiles()) == 0

    def test_only_one_active_profile(self, euicc, sample_profile):
        euicc.install_profile(sample_profile)
        profile2 = sample_profile.copy()
        profile2["iccid"] = "8901000000000000002"
        profile2["imsi"] = "001010123456790"
        euicc.install_profile(profile2)

        euicc.enable_profile("8901000000000000001")
        euicc.enable_profile("8901000000000000002")

        # First profile should be disabled
        for p in euicc.profiles.values():
            if p.iccid == "8901000000000000001":
                assert p.state == ProfileState.DISABLED
            elif p.iccid == "8901000000000000002":
                assert p.state == ProfileState.ENABLED

    def test_duplicate_install_rejected(self, euicc, sample_profile):
        euicc.install_profile(sample_profile)
        with pytest.raises(ValueError, match="already installed"):
            euicc.install_profile(sample_profile)

    def test_enable_nonexistent_profile(self, euicc):
        with pytest.raises(KeyError):
            euicc.enable_profile("9999999999999999")

    def test_profile_persistence(self, tmp_dirs, sample_profile):
        profile_dir, key_dir = tmp_dirs

        # Install and enable a profile
        e1 = VirtualEUICC(profile_dir=profile_dir, key_dir=key_dir)
        e1.initialize()
        e1.install_profile(sample_profile)
        e1.enable_profile("8901000000000000001")

        # Create a new eUICC instance pointing to the same storage
        e2 = VirtualEUICC(profile_dir=profile_dir, key_dir=key_dir)
        e2.initialize()

        assert len(e2.list_profiles()) == 1
        active = e2.get_active_profile()
        assert active is not None
        assert active.iccid == "8901000000000000001"


class TestISDP:
    def test_usim_data(self):
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test",
            ki="aabbccdd" * 4,
            opc="11223344" * 4,
        )
        usim = isdp.get_usim_data()
        assert usim["imsi"] == "001010123456789"
        assert usim["ki"] == "aabbccdd" * 4

    def test_isim_data_derived(self):
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test",
            ki="00" * 16,
            opc="00" * 16,
            mcc="001",
            mnc="01",
        )
        isim = isdp.get_isim_data()
        assert isim is not None
        assert "001010123456789" in isim["impi"]
        assert "3gppnetwork.org" in isim["home_domain"]

    def test_isim_data_explicit(self):
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test",
            ki="00" * 16,
            opc="00" * 16,
            impi="user@ims.example.com",
            impu="sip:user@ims.example.com",
            home_domain="ims.example.com",
        )
        isim = isdp.get_isim_data()
        assert isim["impi"] == "user@ims.example.com"

    def test_serialization_roundtrip(self):
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test123",
            ki="aabb" * 8,
            opc="ccdd" * 8,
            mcc="310",
            mnc="260",
            spn="T-Mobile",
            msisdn="+12025551234",
            state=ProfileState.ENABLED,
            sqn=42,
        )
        data = isdp.to_dict()
        restored = ISDP.from_dict(data)

        assert restored.iccid == isdp.iccid
        assert restored.imsi == isdp.imsi
        assert restored.ki == isdp.ki
        assert restored.state == ProfileState.ENABLED
        assert restored.sqn == 42

    def test_sqn_increment(self):
        isdp = ISDP(
            iccid="test",
            imsi="test",
            aid="test",
            ki="00" * 16,
            opc="00" * 16,
            sqn=100,
        )
        new_sqn = isdp.increment_sqn()
        assert new_sqn == 101
        assert isdp.sqn == 101
