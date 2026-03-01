"""
Android eUICC HAL interface.

Implements the IEuicc HAL interface that Android's EuiccManager uses
to manage eSIM profiles. This is the bridge between Android's eSIM UI
and our virtual eUICC.

Key operations:
- getEid(): Return the eUICC EID
- getDownloadableSubscriptionMetadata(): Get profile metadata
- downloadSubscription(): Download and install a profile
- getEuiccProfileInfoList(): List installed profiles
- switchToSubscription(): Enable/disable profiles
- deleteSubscription(): Delete a profile

Reference: Android IEuicc HAL (hardware/interfaces/radio/config/)
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class EuiccHAL:
    """
    Virtual eUICC HAL implementation.

    Translates Android EuiccManager API calls into commands for
    the virtual eUICC via the RSP service.
    """

    def __init__(
        self,
        euicc_socket: str = "/run/vphone/euicc.sock",
        rsp_socket: str = "/run/vphone/rsp.sock",
    ):
        self.euicc_socket = euicc_socket
        self.rsp_socket = rsp_socket

    async def get_eid(self) -> str:
        """IEuicc::getEid() - Return the EID."""
        resp = await self._euicc_command({"type": "get_info"})
        return resp.get("data", {}).get("eid", "")

    async def get_euicc_info(self) -> dict:
        """Return eUICC information."""
        resp = await self._euicc_command({"type": "get_info"})
        return resp.get("data", {})

    async def get_profile_list(self) -> list[dict]:
        """IEuicc::getEuiccProfileInfoList() - List installed profiles."""
        resp = await self._euicc_command({"type": "list_profiles"})
        profiles = resp.get("data", [])

        # Map to Android EuiccProfileInfo format
        return [
            {
                "iccid": p.get("iccid", ""),
                "accessRules": [],
                "nickname": p.get("spn", ""),
                "serviceProviderName": p.get("spn", ""),
                "profileName": f"{p.get('spn', 'Profile')} ({p.get('mcc', '')}{p.get('mnc', '')})",
                "state": 1 if p.get("state") == "enabled" else 0,  # 0=disabled, 1=enabled
                "carrierIdentifier": {
                    "mcc": p.get("mcc", ""),
                    "mnc": p.get("mnc", ""),
                },
                "profileClass": 2,  # OPERATIONAL
            }
            for p in profiles
        ]

    async def download_subscription(
        self,
        activation_code: str,
        confirmation_code: Optional[str] = None,
        switch_after_download: bool = True,
    ) -> dict:
        """
        IEuicc::downloadSubscription() - Download and install a profile.

        Initiates the RSP profile download flow using the activation code.
        """
        logger.info("eUICC HAL: downloadSubscription(%s)", activation_code[:30])

        result = await self._rsp_command({
            "command": "download",
            "activation_code": activation_code,
            "confirmation_code": confirmation_code,
        })

        if result.get("success") and switch_after_download:
            iccid = result.get("iccid", "")
            if iccid:
                await self.switch_to_subscription(iccid)

        return result

    async def install_profile_direct(self, profile_data: dict) -> dict:
        """Direct profile installation (for testing)."""
        logger.info("eUICC HAL: direct install ICCID=%s", profile_data.get("iccid"))

        return await self._rsp_command({
            "command": "install_direct",
            "profile": profile_data,
        })

    async def switch_to_subscription(self, iccid: str) -> bool:
        """IEuicc::switchToSubscription() - Enable a profile."""
        logger.info("eUICC HAL: switchToSubscription(%s)", iccid)
        resp = await self._euicc_command({
            "type": "enable_profile",
            "iccid": iccid,
        })
        return resp.get("success", False)

    async def delete_subscription(self, iccid: str) -> bool:
        """IEuicc::deleteSubscription() - Delete a profile."""
        logger.info("eUICC HAL: deleteSubscription(%s)", iccid)
        resp = await self._euicc_command({
            "type": "delete_profile",
            "iccid": iccid,
        })
        return resp.get("success", False)

    async def _euicc_command(self, msg: dict) -> dict:
        """Send a command to the eUICC daemon."""
        return await self._send_socket_message(self.euicc_socket, msg)

    async def _rsp_command(self, msg: dict) -> dict:
        """Send a command to the RSP service."""
        return await self._send_socket_message(self.rsp_socket, msg)

    @staticmethod
    async def _send_socket_message(socket_path: str, msg: dict) -> dict:
        """Send a message over a Unix socket and return the response."""
        try:
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
        except Exception as e:
            logger.error("Socket error (%s): %s", socket_path, e)
            return {"error": str(e)}
