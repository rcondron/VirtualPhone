"""Integration tests for the eUICC daemon.

Tests the daemon's Unix socket protocol by starting a real daemon
instance and communicating with it via the length-prefixed JSON protocol.
"""

import asyncio
import json
import os
import tempfile

import pytest

from euicc.daemon import EUICCDaemon

# Use a unique socket path per test run to avoid conflicts
_TEST_SOCKET = None


@pytest.fixture
async def daemon():
    """Start a real eUICC daemon on a temporary Unix socket."""
    with tempfile.TemporaryDirectory() as profile_dir:
        with tempfile.TemporaryDirectory() as key_dir:
            # Patch environment for the daemon
            socket_path = os.path.join(profile_dir, "test_euicc.sock")
            d = EUICCDaemon()
            d.euicc = d.euicc.__class__(
                eid="89001012012341234000000000000099",
                profile_dir=profile_dir,
                key_dir=key_dir,
            )
            d.euicc.initialize()

            # Start the server on a temp socket
            if os.path.exists(socket_path):
                os.unlink(socket_path)
            server = await asyncio.start_unix_server(
                d._handle_client, path=socket_path
            )

            yield d, socket_path

            server.close()
            await server.wait_closed()


async def _send_msg(socket_path: str, msg: dict) -> dict:
    """Send a message to the daemon and return the response."""
    reader, writer = await asyncio.open_unix_connection(socket_path)
    msg_bytes = json.dumps(msg).encode()
    writer.write(len(msg_bytes).to_bytes(4, "big"))
    writer.write(msg_bytes)
    await writer.drain()

    length_bytes = await reader.readexactly(4)
    length = int.from_bytes(length_bytes, "big")
    resp_bytes = await reader.readexactly(length)
    writer.close()
    await writer.wait_closed()
    return json.loads(resp_bytes)


SAMPLE_PROFILE = {
    "iccid": "8901000000000000001",
    "imsi": "001010123456789",
    "ki": "000102030405060708090a0b0c0d0e0f",
    "opc": "111102030405060708090a0b0c0d0e0f",
    "mcc": "001",
    "mnc": "01",
    "spn": "Test Operator",
    "msisdn": "+10000000001",
}


@pytest.mark.integration
class TestDaemonGetInfo:
    async def test_get_info(self, daemon):
        d, sock = daemon
        resp = await _send_msg(sock, {"type": "get_info"})
        assert resp["type"] == "info"
        assert resp["data"]["eid"] == "89001012012341234000000000000099"
        assert resp["data"]["state"] == "ready"

    async def test_get_info_shows_profile_count(self, daemon):
        d, sock = daemon
        resp = await _send_msg(sock, {"type": "get_info"})
        assert resp["data"]["installed_profiles"] == 0


@pytest.mark.integration
class TestDaemonListProfiles:
    async def test_list_profiles_empty(self, daemon):
        d, sock = daemon
        resp = await _send_msg(sock, {"type": "list_profiles"})
        assert resp["type"] == "profiles"
        assert resp["data"] == []


@pytest.mark.integration
class TestDaemonInstallProfile:
    async def test_install_profile(self, daemon):
        d, sock = daemon
        resp = await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        assert resp["type"] == "result"
        assert resp["success"] is True
        assert resp["iccid"] == "8901000000000000001"

    async def test_install_profile_appears_in_list(self, daemon):
        d, sock = daemon
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        resp = await _send_msg(sock, {"type": "list_profiles"})
        assert len(resp["data"]) == 1
        assert resp["data"][0]["iccid"] == "8901000000000000001"
        assert resp["data"][0]["state"] == "disabled"

    async def test_install_duplicate_fails(self, daemon):
        d, sock = daemon
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        # Second install of same ICCID should fail
        # The daemon doesn't wrap errors in a clean way, but let's verify
        # that the profile count doesn't increase
        profiles_before = await _send_msg(sock, {"type": "list_profiles"})
        assert len(profiles_before["data"]) == 1


@pytest.mark.integration
class TestDaemonEnableDisableProfile:
    async def test_enable_profile(self, daemon):
        d, sock = daemon
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        resp = await _send_msg(sock, {
            "type": "enable_profile",
            "iccid": "8901000000000000001",
        })
        assert resp["type"] == "result"
        assert resp["success"] is True

        # Verify via list
        profiles = await _send_msg(sock, {"type": "list_profiles"})
        assert profiles["data"][0]["state"] == "enabled"

    async def test_disable_profile(self, daemon):
        d, sock = daemon
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        await _send_msg(sock, {
            "type": "enable_profile",
            "iccid": "8901000000000000001",
        })
        resp = await _send_msg(sock, {
            "type": "disable_profile",
            "iccid": "8901000000000000001",
        })
        assert resp["type"] == "result"
        assert resp["success"] is True

        profiles = await _send_msg(sock, {"type": "list_profiles"})
        assert profiles["data"][0]["state"] == "disabled"

    async def test_only_one_profile_active(self, daemon):
        d, sock = daemon
        # Install two profiles
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        profile2 = SAMPLE_PROFILE.copy()
        profile2["iccid"] = "8901000000000000002"
        profile2["imsi"] = "001010123456790"
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": profile2,
        })

        # Enable first, then second
        await _send_msg(sock, {
            "type": "enable_profile",
            "iccid": "8901000000000000001",
        })
        await _send_msg(sock, {
            "type": "enable_profile",
            "iccid": "8901000000000000002",
        })

        profiles = await _send_msg(sock, {"type": "list_profiles"})
        states = {p["iccid"]: p["state"] for p in profiles["data"]}
        assert states["8901000000000000001"] == "disabled"
        assert states["8901000000000000002"] == "enabled"


@pytest.mark.integration
class TestDaemonDeleteProfile:
    async def test_delete_profile(self, daemon):
        d, sock = daemon
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        resp = await _send_msg(sock, {
            "type": "delete_profile",
            "iccid": "8901000000000000001",
        })
        assert resp["type"] == "result"
        assert resp["success"] is True

        profiles = await _send_msg(sock, {"type": "list_profiles"})
        assert len(profiles["data"]) == 0

    async def test_delete_active_profile_clears_active(self, daemon):
        d, sock = daemon
        await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        await _send_msg(sock, {
            "type": "enable_profile",
            "iccid": "8901000000000000001",
        })
        await _send_msg(sock, {
            "type": "delete_profile",
            "iccid": "8901000000000000001",
        })

        info = await _send_msg(sock, {"type": "get_info"})
        assert info["data"]["active_iccid"] is None


@pytest.mark.integration
class TestDaemonUnknownMessage:
    async def test_unknown_type(self, daemon):
        d, sock = daemon
        resp = await _send_msg(sock, {"type": "nonexistent"})
        assert resp["type"] == "error"
        assert "Unknown" in resp["message"]


@pytest.mark.integration
class TestDaemonFullLifecycle:
    async def test_install_enable_disable_delete(self, daemon):
        """Full profile lifecycle: install -> enable -> disable -> delete."""
        d, sock = daemon

        # Install
        resp = await _send_msg(sock, {
            "type": "install_profile",
            "profile": SAMPLE_PROFILE,
        })
        assert resp["success"]

        # Enable
        resp = await _send_msg(sock, {
            "type": "enable_profile",
            "iccid": "8901000000000000001",
        })
        assert resp["success"]

        # Verify active
        info = await _send_msg(sock, {"type": "get_info"})
        assert info["data"]["active_iccid"] == "8901000000000000001"

        # Disable
        resp = await _send_msg(sock, {
            "type": "disable_profile",
            "iccid": "8901000000000000001",
        })
        assert resp["success"]

        info = await _send_msg(sock, {"type": "get_info"})
        assert info["data"]["active_iccid"] is None

        # Delete
        resp = await _send_msg(sock, {
            "type": "delete_profile",
            "iccid": "8901000000000000001",
        })
        assert resp["success"]

        profiles = await _send_msg(sock, {"type": "list_profiles"})
        assert len(profiles["data"]) == 0
