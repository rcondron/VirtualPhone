"""
Tests for VoWiFi (Phase 3) — IPsec tunnel, EAP-AKA, quintuplet provisioning.

Tests cover:
1. NAI (Network Access Identifier) construction
2. swanctl configuration generation
3. strongswan.conf configuration generation
4. VoWiFi tunnel state machine
5. Tunnel info extraction (virtual IP, P-CSCF, DNS)
6. DPD monitoring logic
7. Quintuplet provisioning (simaka-sql schema)
8. Quintuplet Milenage vector validity
9. VoWiFi status API endpoint
10. VoWiFi integration with IMS service
"""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import struct
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ims.vowifi import VoWiFiConfig, VoWiFiState, VoWiFiTunnel, get_vowifi_state, _vowifi_state


# =============================================================================
# NAI Construction
# =============================================================================

class TestNAIConstruction:
    """Test Network Access Identifier building per 3GPP TS 23.003."""

    def test_nai_basic(self):
        """NAI format: 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org"""
        nai = VoWiFiTunnel.build_nai("001010123456789", "001", "01")
        assert nai == "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"

    def test_nai_three_digit_mnc(self):
        """MNC should be zero-padded to 3 digits."""
        nai = VoWiFiTunnel.build_nai("310260123456789", "310", "260")
        assert nai == "0310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org"

    def test_nai_two_digit_mnc_padded(self):
        """2-digit MNC gets zero-padded."""
        nai = VoWiFiTunnel.build_nai("001010123456789", "001", "01")
        assert "mnc001" in nai

    def test_nai_prefix_is_zero(self):
        """NAI permanent identity prefix is '0' (per TS 23.003)."""
        nai = VoWiFiTunnel.build_nai("001010123456789", "001", "01")
        assert nai.startswith("0001010123456789@")

    def test_nai_via_tunnel_instance(self):
        """NAI from tunnel matches static method."""
        config = VoWiFiConfig(imsi="001010123456789", mcc="001", mnc="01")
        tunnel = VoWiFiTunnel(config)
        assert tunnel._build_nai() == VoWiFiTunnel.build_nai("001010123456789", "001", "01")

    def test_nai_different_plmns(self):
        """Test NAI for various PLMN identifiers."""
        # T-Mobile US
        nai = VoWiFiTunnel.build_nai("310260999999999", "310", "260")
        assert "mnc260.mcc310" in nai

        # Deutsche Telekom
        nai = VoWiFiTunnel.build_nai("262011234567890", "262", "01")
        assert "mnc001.mcc262" in nai


# =============================================================================
# swanctl Configuration
# =============================================================================

class TestSwanctlConfig:
    """Test strongSwan swanctl configuration generation."""

    def _make_tunnel_with_config(self, **kwargs) -> VoWiFiTunnel:
        defaults = {
            "epdg_address": "172.28.0.45",
            "mcc": "001",
            "mnc": "01",
            "imsi": "001010123456789",
        }
        defaults.update(kwargs)
        return VoWiFiTunnel(VoWiFiConfig(**defaults))

    def test_swanctl_config_has_epdg_address(self, tmp_path):
        """Config contains remote_addrs pointing to ePDG."""
        tunnel = self._make_tunnel_with_config()
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        nai = tunnel._build_nai()
        tunnel._write_swanctl_config(nai)

        conf = (tmp_path / "vowifi.conf").read_text()
        assert "remote_addrs = 172.28.0.45" in conf

    def test_swanctl_config_has_eap_aka(self, tmp_path):
        """Config uses EAP-AKA authentication."""
        tunnel = self._make_tunnel_with_config()
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        tunnel._write_swanctl_config(tunnel._build_nai())

        conf = (tmp_path / "vowifi.conf").read_text()
        assert "auth = eap-aka" in conf

    def test_swanctl_config_has_nai_identity(self, tmp_path):
        """Config includes the NAI as EAP identity."""
        tunnel = self._make_tunnel_with_config()
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        nai = tunnel._build_nai()
        tunnel._write_swanctl_config(nai)

        conf = (tmp_path / "vowifi.conf").read_text()
        assert f"eap_id = {nai}" in conf

    def test_swanctl_config_has_vips(self, tmp_path):
        """Config requests virtual IP from ePDG."""
        tunnel = self._make_tunnel_with_config()
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        tunnel._write_swanctl_config(tunnel._build_nai())

        conf = (tmp_path / "vowifi.conf").read_text()
        assert "vips = 0.0.0.0" in conf

    def test_swanctl_config_has_dpd(self, tmp_path):
        """Config includes DPD settings."""
        tunnel = self._make_tunnel_with_config(dpd_delay=60)
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        tunnel._write_swanctl_config(tunnel._build_nai())

        conf = (tmp_path / "vowifi.conf").read_text()
        assert "dpd_delay = 60s" in conf

    def test_swanctl_config_has_child_sa(self, tmp_path):
        """Config defines a child SA with ESP proposals."""
        tunnel = self._make_tunnel_with_config()
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        tunnel._write_swanctl_config(tunnel._build_nai())

        conf = (tmp_path / "vowifi.conf").read_text()
        assert "vowifi-child" in conf
        assert "esp_proposals" in conf
        assert "dpd_action = restart" in conf

    def test_swanctl_config_custom_proposals(self, tmp_path):
        """Config respects custom IKE/ESP proposals."""
        tunnel = self._make_tunnel_with_config(
            ike_proposals="aes128-sha256-modp1024",
            esp_proposals="aes128-sha1",
        )
        tunnel.SWANCTL_CONF_DIR = str(tmp_path)
        tunnel._write_swanctl_config(tunnel._build_nai())

        conf = (tmp_path / "vowifi.conf").read_text()
        assert "aes128-sha256-modp1024" in conf
        assert "aes128-sha1" in conf


# =============================================================================
# strongswan.conf for simaka-sql
# =============================================================================

class TestStrongSwanConf:
    """Test strongswan.conf generation for simaka-sql plugin."""

    def test_writes_simaka_sql_config(self, tmp_path):
        """strongswan.conf includes simaka-sql with DB path."""
        config = VoWiFiConfig(
            epdg_address="172.28.0.45",
            quintuplet_db=str(tmp_path / "test.db"),
        )
        tunnel = VoWiFiTunnel(config)

        # Create a fake strongswan.d directory
        conf_dir = tmp_path / "strongswan.d"
        conf_dir.mkdir()

        with patch("ims.vowifi.Path") as mock_path:
            # Make Path("/etc/strongswan.d") point to our tmp dir
            def path_side_effect(p):
                if p == "/etc/strongswan.d":
                    return conf_dir
                return Path(p)
            mock_path.side_effect = path_side_effect
            mock_path.return_value.exists.return_value = True

            tunnel._write_strongswan_conf()

        conf_file = conf_dir / "vowifi.conf"
        if conf_file.exists():
            content = conf_file.read_text()
            assert "eap-simaka-sql" in content
            assert "test.db" in content


# =============================================================================
# Tunnel State Machine
# =============================================================================

class TestTunnelStateMachine:
    """Test VoWiFi tunnel state transitions."""

    def test_initial_state_disconnected(self):
        tunnel = VoWiFiTunnel(VoWiFiConfig())
        assert tunnel.state == VoWiFiState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_connect_fails_without_epdg(self):
        """Connect fails immediately if no ePDG address."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address=""))
        result = await tunnel.connect()
        assert result is False
        assert tunnel.state == VoWiFiState.FAILED

    @pytest.mark.asyncio
    async def test_disconnect_resets_state(self):
        """Disconnect resets all state to defaults."""
        config = VoWiFiConfig(epdg_address="172.28.0.45")
        tunnel = VoWiFiTunnel(config)
        tunnel.state = VoWiFiState.CONNECTED
        tunnel._tunnel_ip = "10.47.0.1"
        tunnel._pcscf_addresses = ["172.28.0.41"]
        tunnel._dns_servers = ["172.28.0.50"]

        await tunnel.disconnect()

        assert tunnel.state == VoWiFiState.DISCONNECTED
        assert tunnel._tunnel_ip is None
        assert tunnel._pcscf_addresses == []
        assert tunnel._dns_servers == []

    def test_get_tunnel_info(self):
        """get_tunnel_info returns complete state dict."""
        config = VoWiFiConfig(epdg_address="172.28.0.45")
        tunnel = VoWiFiTunnel(config)
        tunnel.state = VoWiFiState.CONNECTED
        tunnel._tunnel_ip = "10.47.0.1"
        tunnel._pcscf_addresses = ["172.28.0.41"]

        info = tunnel.get_tunnel_info()
        assert info["state"] == "connected"
        assert info["epdg"] == "172.28.0.45"
        assert info["tunnel_ip"] == "10.47.0.1"
        assert info["pcscf_addresses"] == ["172.28.0.41"]

    def test_pcscf_address_property(self):
        """pcscf_address returns first P-CSCF or None."""
        tunnel = VoWiFiTunnel(VoWiFiConfig())
        assert tunnel.pcscf_address is None

        tunnel._pcscf_addresses = ["172.28.0.41", "172.28.0.42"]
        assert tunnel.pcscf_address == "172.28.0.41"

    def test_tunnel_ip_property(self):
        tunnel = VoWiFiTunnel(VoWiFiConfig())
        assert tunnel.tunnel_ip is None

        tunnel._tunnel_ip = "10.47.0.5"
        assert tunnel.tunnel_ip == "10.47.0.5"


# =============================================================================
# Tunnel Info Extraction
# =============================================================================

class TestTunnelInfoExtraction:
    """Test parsing of tunnel information from swanctl output."""

    @pytest.mark.asyncio
    async def test_extract_virtual_ip(self):
        """Extract virtual IP from swanctl --list-sas output."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address="172.28.0.45"))

        swanctl_output = """vowifi: #1, ESTABLISHED
  local  '0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org'
  remote 'epdg.epc.mnc001.mcc001.3gppnetwork.org'
  local-vips = {10.47.0.2}
  vowifi-child: #1, INSTALLED
    local  10.47.0.2/32
"""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (swanctl_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await tunnel._extract_tunnel_info()

        assert tunnel._tunnel_ip == "10.47.0.2"

    @pytest.mark.asyncio
    async def test_extract_dns_servers(self):
        """Extract DNS servers from CFG_REPLY."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address="172.28.0.45"))

        swanctl_output = """vowifi: #1, ESTABLISHED
  local-vips = {10.47.0.2}
  dns = {172.28.0.50}
  vowifi-child: #1, INSTALLED
"""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (swanctl_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await tunnel._extract_tunnel_info()

        assert "172.28.0.50" in tunnel._dns_servers

    @pytest.mark.asyncio
    async def test_extract_pcscf_from_vendor_attr(self):
        """Extract P-CSCF from 3GPP vendor attribute in CFG_REPLY."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address="172.28.0.45"))

        swanctl_output = """vowifi: #1, ESTABLISHED
  local-vips = {10.47.0.2}
  16384-10415 = {172.28.0.41}
  vowifi-child: #1, INSTALLED
"""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (swanctl_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await tunnel._extract_tunnel_info()

        assert "172.28.0.41" in tunnel._pcscf_addresses

    @pytest.mark.asyncio
    async def test_pcscf_fallback_to_env(self):
        """Fall back to VPHONE_IMS_PROXY env if no P-CSCF from tunnel."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address="172.28.0.45"))

        swanctl_output = """vowifi: #1, ESTABLISHED
  local-vips = {10.47.0.2}
  vowifi-child: #1, INSTALLED
"""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (swanctl_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.dict(os.environ, {"VPHONE_IMS_PROXY": "172.28.0.41"}):
                await tunnel._extract_tunnel_info()

        assert "172.28.0.41" in tunnel._pcscf_addresses

    @pytest.mark.asyncio
    async def test_extract_ip_from_interface(self):
        """Fallback: Extract tunnel IP from ip addr output."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address="172.28.0.45"))

        ip_output = """1: lo: <LOOPBACK> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST> mtu 1500
    inet 172.28.0.20/24 scope global eth0
3: vti0: <POINTOPOINT> mtu 1400
    inet 10.47.0.3/32 scope global vti0
"""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (ip_output.encode(), b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await tunnel._extract_ip_from_interface()

        assert tunnel._tunnel_ip == "10.47.0.3"

    @pytest.mark.asyncio
    async def test_extract_handles_empty_output(self):
        """Gracefully handle empty swanctl output."""
        tunnel = VoWiFiTunnel(VoWiFiConfig(epdg_address="172.28.0.45"))

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await tunnel._extract_tunnel_info()

        assert tunnel._tunnel_ip is None


# =============================================================================
# Quintuplet Provisioning (simaka-sql)
# =============================================================================

class TestQuintupletProvisioning:
    """Test EAP-AKA quintuplet generation for simaka-sql."""

    def _test_ki(self):
        return bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def _test_opc(self):
        return bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_generate_quintuplets(self):
        """Generate quintuplets using Milenage."""
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from scripts.provision_epdg import generate_quintuplets

        quints = generate_quintuplets(
            self._test_ki(), self._test_opc(),
            "001010123456789", count=5, sqn_start=32,
        )
        assert len(quints) == 5

        # Each quintuplet: (permanent, rand, autn, ik, ck, res) — simaka-sql order
        for perm, rand, autn, ik, ck, res in quints:
            assert perm == "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
            assert len(rand) == 16
            assert len(autn) == 16  # SQN^AK (6) + AMF (2) + MAC-A (8)
            assert len(res) == 8
            assert len(ck) == 16
            assert len(ik) == 16

    def test_quintuplets_unique_rand(self):
        """Each quintuplet has a unique RAND."""
        from scripts.provision_epdg import generate_quintuplets

        quints = generate_quintuplets(
            self._test_ki(), self._test_opc(),
            "001010123456789", count=10,
        )
        rands = [q[1] for q in quints]
        assert len(set(rands)) == 10

    def test_create_database(self):
        """Create SQLite database with simaka-sql schema."""
        from scripts.provision_epdg import generate_quintuplets, create_database

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            quints = generate_quintuplets(
                self._test_ki(), self._test_opc(),
                "001010123456789", count=5,
            )
            create_database(db_path, quints)

            conn = sqlite3.connect(db_path)

            # Verify table exists
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            assert "quintuplets" in table_names

            # Verify row count
            count = conn.execute("SELECT COUNT(*) FROM quintuplets").fetchone()[0]
            assert count == 5

            # Verify schema
            row = conn.execute(
                "SELECT permanent, rand, autn, ik, ck, res, used FROM quintuplets LIMIT 1"
            ).fetchone()
            perm, rand, autn, ik, ck, res, used = row
            assert perm == "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
            assert len(rand) == 16
            assert len(autn) == 16
            assert len(ik) == 16
            assert len(ck) == 16
            assert len(res) == 8
            assert used == 0

            conn.close()

    def test_quintuplet_milenage_validity(self):
        """Verify quintuplets are valid Milenage vectors (AUTN structure)."""
        from scripts.provision_epdg import generate_quintuplets
        from euicc.crypto.milenage import Milenage

        ki = self._test_ki()
        opc = self._test_opc()

        quints = generate_quintuplets(ki, opc, "001010123456789", count=3, sqn_start=32)

        mil = Milenage(ki, opc)

        for perm, rand, autn, ik, ck, res in quints:
            # Verify that the UE (with the same Ki/OPc) can authenticate
            # with the generated vector
            result = mil.authenticate(rand, autn, 0)
            assert result is not None, "Milenage authenticate() should succeed"

            auth_res, auth_ck, auth_ik = result
            assert auth_res == res
            assert auth_ck == ck
            assert auth_ik == ik

    def test_quintuplet_autn_structure(self):
        """AUTN = (SQN XOR AK) || AMF || MAC-A."""
        from scripts.provision_epdg import generate_quintuplets

        quints = generate_quintuplets(
            self._test_ki(), self._test_opc(),
            "001010123456789", count=1, sqn_start=64,
        )
        _, rand, autn, _, _, _ = quints[0]

        # AUTN is 16 bytes: SQN^AK (6) + AMF (2) + MAC-A (8)
        assert len(autn) == 16
        sqn_xor_ak = autn[:6]
        amf = autn[6:8]
        mac_a = autn[8:16]

        # AMF should be 0x8000 (standard)
        assert amf == bytes.fromhex("8000")
        # MAC-A should be 8 bytes
        assert len(mac_a) == 8


# =============================================================================
# VoWiFi Module State (for management API)
# =============================================================================

class TestVoWiFiModuleState:
    """Test module-level state shared with management API."""

    def test_initial_state(self):
        """Initial module state is disconnected."""
        state = get_vowifi_state()
        assert state["state"] == "disconnected"
        assert state["tunnel_up"] is False

    def test_state_returns_copy(self):
        """get_vowifi_state returns a copy, not a reference."""
        state1 = get_vowifi_state()
        state2 = get_vowifi_state()
        state1["state"] = "modified"
        assert state2["state"] != "modified"

    def test_state_has_expected_fields(self):
        """Module state includes all expected fields."""
        state = get_vowifi_state()
        expected_keys = {"state", "tunnel_up", "epdg", "tunnel_ip",
                         "pcscf_addresses", "dns_servers", "dpd_ok"}
        assert expected_keys == set(state.keys())


# =============================================================================
# VoWiFi Status API Endpoint
# =============================================================================

class TestVoWiFiStatusAPI:
    """Test /status/vowifi management API endpoint."""

    @pytest.mark.asyncio
    async def test_vowifi_status_returns_state(self):
        """API endpoint returns VoWiFi module state."""
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/status/vowifi")
            assert resp.status_code == 200
            data = resp.json()
            assert "state" in data
            assert "tunnel_up" in data
            assert "epdg" in data

    @pytest.mark.asyncio
    async def test_vowifi_status_not_tunnel_up_initially(self):
        """VoWiFi tunnel is not up initially."""
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/status/vowifi")
            data = resp.json()
            assert data["tunnel_up"] is False


# =============================================================================
# EAP-AKA Shared Quintuplet Flow
# =============================================================================

class TestEAPAKASharedQuintuplets:
    """Test that quintuplets work for both server and client roles."""

    def test_server_picks_client_verifies(self):
        """Server picks a quintuplet, client can verify using Milenage."""
        from scripts.provision_epdg import generate_quintuplets, create_database
        from euicc.crypto.milenage import Milenage

        ki = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
        opc = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")

        quints = generate_quintuplets(ki, opc, "001010123456789", count=5, sqn_start=32)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            create_database(db_path, quints)

            # Server role: pick first unused quintuplet
            conn = sqlite3.connect(db_path)
            row = conn.execute(
                "SELECT rand, autn, ik, ck, res FROM quintuplets "
                "WHERE permanent = ? AND used = 0 LIMIT 1",
                ("0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",),
            ).fetchone()
            conn.close()

            assert row is not None
            server_rand, server_autn, server_ik, server_ck, server_xres = row

            # Client role: receive RAND/AUTN, compute using Milenage
            mil = Milenage(ki, opc)
            result = mil.authenticate(server_rand, server_autn, 0)
            assert result is not None

            client_res, client_ck, client_ik = result

            # Verify: client's response matches server's expected
            assert client_res == server_xres
            assert client_ck == server_ck
            assert client_ik == server_ik

    def test_client_lookup_by_rand(self):
        """Client can look up quintuplet by RAND (simaka-sql card interface)."""
        from scripts.provision_epdg import generate_quintuplets, create_database

        ki = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
        opc = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")

        quints = generate_quintuplets(ki, opc, "001010123456789", count=5, sqn_start=32)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            create_database(db_path, quints)

            # Server sends RAND from first quintuplet
            server_rand = quints[0][1]

            # Client looks up by permanent + rand
            conn = sqlite3.connect(db_path)
            row = conn.execute(
                "SELECT ck, ik, res FROM quintuplets WHERE permanent = ? AND rand = ?",
                ("0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org", server_rand),
            ).fetchone()
            conn.close()

            assert row is not None
            ck, ik, res = row
            assert len(ck) == 16
            assert len(ik) == 16
            assert len(res) == 8

    def test_multiple_subscribers(self):
        """Provisioning supports multiple subscribers."""
        from scripts.provision_epdg import generate_quintuplets, create_database

        ki1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        opc1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ki2 = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
        opc2 = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")

        quints1 = generate_quintuplets(ki1, opc1, "001010123456789", count=3)
        quints2 = generate_quintuplets(ki2, opc2, "001010987654321", count=3)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            create_database(db_path, quints1 + quints2)

            conn = sqlite3.connect(db_path)
            count = conn.execute("SELECT COUNT(*) FROM quintuplets").fetchone()[0]
            assert count == 6

            # Each subscriber has 3 quintuplets
            c1 = conn.execute(
                "SELECT COUNT(*) FROM quintuplets WHERE permanent LIKE '%001010123456789%'"
            ).fetchone()[0]
            c2 = conn.execute(
                "SELECT COUNT(*) FROM quintuplets WHERE permanent LIKE '%001010987654321%'"
            ).fetchone()[0]
            conn.close()

            assert c1 == 3
            assert c2 == 3


# =============================================================================
# ePDG Configuration Files
# =============================================================================

class TestEPDGConfig:
    """Test ePDG strongSwan configuration files."""

    def test_epdg_swanctl_has_eap_aka(self):
        """ePDG swanctl.conf uses EAP-AKA for remote auth."""
        conf_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "epdg", "swanctl.conf"
        )
        content = Path(conf_path).read_text()
        assert "eap-aka" in content
        assert "remote {" in content

    def test_epdg_swanctl_has_pool(self):
        """ePDG swanctl.conf defines a virtual IP pool."""
        conf_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "epdg", "swanctl.conf"
        )
        content = Path(conf_path).read_text()
        assert "vowifi-pool" in content
        assert "10.47.0.0/24" in content

    def test_epdg_swanctl_has_dpd(self):
        """ePDG swanctl.conf has DPD settings."""
        conf_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "epdg", "swanctl.conf"
        )
        content = Path(conf_path).read_text()
        assert "dpd_delay" in content
        assert "dpd_timeout" in content

    def test_epdg_strongswan_has_simaka_sql(self):
        """ePDG strongswan.conf enables simaka-sql plugin."""
        conf_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "epdg", "strongswan.conf"
        )
        content = Path(conf_path).read_text()
        assert "eap-simaka-sql" in content
        assert "sqlite://" in content

    def test_epdg_init_script_executable_structure(self):
        """ePDG init script has expected structure."""
        script_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "epdg", "epdg_init.sh"
        )
        content = Path(script_path).read_text()
        assert "#!/usr/bin/env bash" in content
        assert "charon" in content
        assert "epdg.cert.pem" in content

    def test_epdg_dockerfile_has_strongswan(self):
        """ePDG Dockerfile installs strongSwan with EAP plugins."""
        dockerfile_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "epdg", "Dockerfile"
        )
        content = Path(dockerfile_path).read_text()
        assert "strongswan" in content
        assert "libcharon-extra-plugins" in content
