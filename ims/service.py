"""
IMS service - runs IMS registration and manages VoWiFi/VoLTE.

Background service that:
1. Waits for an active eSIM profile
2. Fetches profile credentials (Ki, OPc, ISIM) from the eUICC daemon
3. Establishes VoWiFi tunnel if configured
4. Registers with IMS core via P-CSCF using AKA authentication
5. Maintains registration with periodic re-registration
6. Exposes registration state for the management API
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

from ims.registration import IMSRegistration, IMSCredentials, IMSConfig, IMSRegState
from ims.vowifi import VoWiFiTunnel, VoWiFiConfig

logging.basicConfig(
    level=getattr(logging, os.environ.get("VPHONE_LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ims.service")

EUICC_SOCKET = "/run/vphone/euicc.sock"

# Global registration state shared with the management API
_ims_state: dict = {
    "registered": False,
    "state": "not_registered",
    "domain": "",
    "pcscf": "",
    "impi": "",
}


def get_ims_state() -> dict:
    """Return the current IMS registration state (called by management API)."""
    return dict(_ims_state)


async def _send_euicc(msg: dict) -> dict:
    """Send a message to the eUICC daemon and return the response."""
    reader, writer = await asyncio.open_unix_connection(EUICC_SOCKET)
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


async def get_active_profile() -> dict | None:
    """Query the eUICC daemon for the active profile."""
    try:
        resp = await _send_euicc({"type": "list_profiles"})
        profiles = resp.get("data", [])
        for p in profiles:
            if p.get("state") == "enabled":
                return p
        return None
    except Exception as e:
        logger.debug("Could not query eUICC: %s", e)
        return None


async def get_profile_credentials(iccid: str) -> dict | None:
    """Get full profile credentials (Ki, OPc, ISIM) from eUICC daemon."""
    try:
        resp = await _send_euicc({"type": "get_profile_credentials", "iccid": iccid})
        if resp.get("type") == "error":
            logger.warning("Failed to get credentials: %s", resp.get("message"))
            return None
        return resp.get("data")
    except Exception as e:
        logger.debug("Could not get credentials: %s", e)
        return None


async def main():
    global _ims_state

    ims_domain = os.environ.get("VPHONE_IMS_DOMAIN", "")
    ims_proxy = os.environ.get("VPHONE_IMS_PROXY", "")
    vowifi_epdg = os.environ.get("VPHONE_VOWIFI_EPDG", "")

    logger.info("IMS service starting (domain=%s, proxy=%s)", ims_domain, ims_proxy)
    _ims_state["domain"] = ims_domain
    _ims_state["pcscf"] = ims_proxy

    # Wait for eUICC daemon and an active profile
    profile = None
    for i in range(60):
        profile = await get_active_profile()
        if profile:
            break
        await asyncio.sleep(5)

    if not profile:
        logger.warning("No active eSIM profile found. IMS service idle.")
        # Stay alive and periodically check
        while True:
            await asyncio.sleep(30)
            profile = await get_active_profile()
            if profile:
                break

    iccid = profile.get("iccid", "")
    imsi = profile.get("imsi", "")
    mcc = profile.get("mcc", "001")
    mnc = profile.get("mnc", "01")
    logger.info("Active profile found: ICCID=%s, IMSI=%s", iccid, imsi)

    # Fetch full credentials (Ki, OPc, ISIM data) from the eUICC
    cred_data = await get_profile_credentials(iccid)
    if cred_data:
        ki = bytes.fromhex(cred_data.get("ki", "00" * 16))
        opc = bytes.fromhex(cred_data.get("opc", "00" * 16))
        sqn = cred_data.get("sqn", 0)
        logger.info("Loaded credentials: Ki=%s..., OPc=%s..., SQN=%d",
                     ki[:4].hex(), opc[:4].hex(), sqn)
    else:
        logger.warning("Could not fetch credentials, using zeros")
        ki = b"\x00" * 16
        opc = b"\x00" * 16
        sqn = 0

    # Build IMS domain
    domain = ims_domain or f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"

    # ISIM identities (use profile data if available, else derive from IMSI)
    impi = cred_data.get("impi", f"{imsi}@{domain}") if cred_data else f"{imsi}@{domain}"
    impu = cred_data.get("impu", f"sip:{imsi}@{domain}") if cred_data else f"sip:{imsi}@{domain}"
    home_domain = cred_data.get("home_domain", domain) if cred_data else domain

    # VoWiFi: Establish IPsec tunnel first
    if vowifi_epdg:
        logger.info("VoWiFi mode: connecting to ePDG %s", vowifi_epdg)
        vowifi = VoWiFiTunnel(VoWiFiConfig(
            epdg_address=vowifi_epdg,
            mcc=mcc,
            mnc=mnc,
            imsi=imsi,
        ))
        if await vowifi.connect():
            logger.info("VoWiFi tunnel established")
            # Use P-CSCF from tunnel
            if vowifi.pcscf_address:
                ims_proxy = vowifi.pcscf_address
        else:
            logger.error("VoWiFi tunnel failed, falling back to direct IMS")

    if not ims_proxy:
        logger.warning("No P-CSCF address available. IMS registration skipped.")
        _ims_state["state"] = "no_pcscf"
        while True:
            await asyncio.sleep(60)

    # IMS Registration with real credentials
    creds = IMSCredentials(
        impi=impi,
        impu=impu,
        home_domain=home_domain,
        ki=ki,
        opc=opc,
        sqn=sqn,
    )

    ims_config = IMSConfig(
        pcscf_address=ims_proxy,
        pcscf_port=5060,
        realm=home_domain,
    )

    _ims_state.update({
        "domain": home_domain,
        "pcscf": ims_proxy,
        "impi": impi,
        "state": "registering",
    })

    reg = IMSRegistration(credentials=creds, config=ims_config)

    if await reg.register():
        logger.info("IMS registration successful")
        _ims_state.update({
            "registered": True,
            "state": "registered",
        })
    else:
        logger.error("IMS registration failed")
        _ims_state.update({
            "registered": False,
            "state": reg.state.value,
        })

    # Keep the service running and update state
    while True:
        _ims_state["state"] = reg.state.value
        _ims_state["registered"] = reg.state == IMSRegState.REGISTERED
        await asyncio.sleep(60)


def run():
    """Synchronous entry point for the IMS service."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: loop.stop())
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    run()
