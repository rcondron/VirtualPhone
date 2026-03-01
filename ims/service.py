"""
IMS service - runs IMS registration and manages VoWiFi/VoLTE.

Background service that:
1. Waits for an active eSIM profile
2. Establishes VoWiFi tunnel if configured
3. Registers with IMS core
4. Maintains registration with periodic re-registration
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

from ims.registration import IMSRegistration, IMSCredentials, IMSConfig
from ims.vowifi import VoWiFiTunnel, VoWiFiConfig

logging.basicConfig(
    level=getattr(logging, os.environ.get("VPHONE_LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ims.service")

EUICC_SOCKET = "/run/vphone/euicc.sock"


async def get_active_profile() -> dict | None:
    """Query the eUICC daemon for the active profile."""
    try:
        reader, writer = await asyncio.open_unix_connection(EUICC_SOCKET)
        msg = json.dumps({"type": "list_profiles"}).encode()
        writer.write(len(msg).to_bytes(4, "big"))
        writer.write(msg)
        await writer.drain()

        length_bytes = await reader.readexactly(4)
        length = int.from_bytes(length_bytes, "big")
        resp_bytes = await reader.readexactly(length)
        writer.close()
        await writer.wait_closed()

        resp = json.loads(resp_bytes)
        profiles = resp.get("data", [])
        for p in profiles:
            if p.get("state") == "enabled":
                return p
        return None
    except Exception as e:
        logger.debug("Could not query eUICC: %s", e)
        return None


async def get_profile_credentials(iccid: str) -> dict | None:
    """Get full profile credentials from eUICC daemon."""
    try:
        reader, writer = await asyncio.open_unix_connection(EUICC_SOCKET)
        # Send APDU to read ISIM data
        msg = json.dumps({"type": "get_info"}).encode()
        writer.write(len(msg).to_bytes(4, "big"))
        writer.write(msg)
        await writer.drain()

        length_bytes = await reader.readexactly(4)
        length = int.from_bytes(length_bytes, "big")
        resp_bytes = await reader.readexactly(length)
        writer.close()
        await writer.wait_closed()

        return json.loads(resp_bytes).get("data")
    except Exception as e:
        logger.debug("Could not get credentials: %s", e)
        return None


async def main():
    ims_domain = os.environ.get("VPHONE_IMS_DOMAIN", "")
    ims_proxy = os.environ.get("VPHONE_IMS_PROXY", "")
    vowifi_epdg = os.environ.get("VPHONE_VOWIFI_EPDG", "")

    logger.info("IMS service starting (domain=%s, proxy=%s)", ims_domain, ims_proxy)

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

    logger.info("Active profile found: ICCID=%s, IMSI=%s", profile.get("iccid"), profile.get("imsi"))

    # Build IMS credentials
    imsi = profile.get("imsi", "")
    mcc = profile.get("mcc", "001")
    mnc = profile.get("mnc", "01")
    domain = ims_domain or f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"

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
        while True:
            await asyncio.sleep(60)

    # IMS Registration
    creds = IMSCredentials(
        impi=f"{imsi}@{domain}",
        impu=f"sip:{imsi}@{domain}",
        home_domain=domain,
        ki=b"\x00" * 16,  # Will be fetched from profile on actual auth
        opc=b"\x00" * 16,
    )

    ims_config = IMSConfig(
        pcscf_address=ims_proxy,
        pcscf_port=5060,
        realm=domain,
    )

    reg = IMSRegistration(credentials=creds, config=ims_config)

    if await reg.register():
        logger.info("IMS registration successful")
    else:
        logger.error("IMS registration failed")

    # Keep the service running
    while True:
        await asyncio.sleep(60)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: loop.stop())
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
