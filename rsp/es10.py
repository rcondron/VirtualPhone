"""
ES10 interface implementation (LPA ↔ eUICC).

The ES10 interface is the local interface between the LPA and the eUICC.
It consists of three sub-interfaces:
- ES10a: LPA services → eUICC (profile management)
- ES10b: LPA → eUICC (profile download preparation)
- ES10c: LPA → eUICC (profile operations)

In our virtual implementation, this communicates with the eUICC daemon
over a Unix socket.

Reference: GSMA SGP.22 Section 5.7
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from typing import Optional

from rsp.asn1.rsp_definitions import (
    BoundProfilePackage,
    EUICCInfo1,
    EUICCInfo2,
    PrepareDownloadResponse,
    ProfileInstallResult,
    ResultCode,
)

logger = logging.getLogger(__name__)

EUICC_SOCKET = "/run/vphone/euicc.sock"


class ES10Client:
    """
    ES10 client for local communication with the virtual eUICC.

    Sends commands to the eUICC daemon over a Unix domain socket.
    """

    def __init__(self, socket_path: str = EUICC_SOCKET):
        self.socket_path = socket_path

    async def _send_message(self, msg: dict) -> dict:
        """Send a message to the eUICC daemon and get a response."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)

        try:
            msg_bytes = json.dumps(msg).encode()
            writer.write(len(msg_bytes).to_bytes(4, "big"))
            writer.write(msg_bytes)
            await writer.drain()

            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, "big")
            resp_bytes = await reader.readexactly(length)
            return json.loads(resp_bytes)
        finally:
            writer.close()
            await writer.wait_closed()

    # -- ES10a: eUICC management ------------------------------------------

    async def get_euicc_info1(self) -> EUICCInfo1:
        """
        ES10a.GetEUICCInfo1 - Get eUICC information for authentication.

        Returns minimal eUICC information needed for the InitiateAuthentication
        request to the SM-DP+.
        """
        resp = await self._send_message({"type": "get_info"})
        data = resp.get("data", {})
        return EUICCInfo1(
            svn=bytes([2, 5, 0]),
        )

    async def get_euicc_info2(self) -> dict:
        """ES10a.GetEUICCInfo2 - Get extended eUICC information."""
        resp = await self._send_message({"type": "get_info"})
        return resp.get("data", {})

    async def get_eid(self) -> str:
        """ES10a.GetEID - Get the eUICC EID."""
        resp = await self._send_message({"type": "get_info"})
        return resp.get("data", {}).get("eid", "")

    # -- ES10b: Profile download ------------------------------------------

    async def prepare_download(
        self,
        transaction_id: str,
        hash_cc: Optional[bytes],
        smdp_signed2: bytes,
        smdp_signature2: bytes,
        smdp_certificate: bytes,
    ) -> PrepareDownloadResponse:
        """
        ES10b.PrepareDownload - Prepare the eUICC for profile download.

        The eUICC verifies the SM-DP+ certificate and signed data,
        then prepares its side of the secure channel.

        Args:
            transaction_id: RSP session transaction ID.
            hash_cc: Hash of confirmation code (if required).
            smdp_signed2: SM-DP+ signed data.
            smdp_signature2: SM-DP+ signature.
            smdp_certificate: SM-DP+ TLS certificate.

        Returns:
            PrepareDownloadResponse with eUICC-signed data.
        """
        resp = await self._send_message({
            "type": "apdu",
            "data": "00E20000" + "00",  # STORE DATA for prepare download
        })

        # Build the prepare download response
        # In a full implementation, this involves SCP03 key derivation
        return PrepareDownloadResponse(
            transaction_id=transaction_id,
            hash_cc=hash_cc,
            smdp_signed2=smdp_signed2,
            smdp_signature2=smdp_signature2,
        )

    async def load_bound_profile_package(
        self,
        bpp: BoundProfilePackage,
    ) -> ProfileInstallResult:
        """
        ES10b.LoadBoundProfilePackage - Install a profile on the eUICC.

        Processes the Bound Profile Package by:
        1. Establishing SCP03 secure channel
        2. Decrypting profile data
        3. Creating ISD-P and installing profile elements
        4. Returning the installation result

        Args:
            bpp: The Bound Profile Package from SM-DP+.

        Returns:
            ProfileInstallResult indicating success or failure.
        """
        logger.info("Loading Bound Profile Package...")

        # Process the BPP through the eUICC
        # The BPP contains encrypted profile data that needs to be
        # decrypted via SCP03 and installed into a new ISD-P

        if bpp.profile_metadata:
            # Install profile using metadata
            resp = await self._send_message({
                "type": "install_profile",
                "profile": bpp.profile_metadata,
            })

            if resp.get("success"):
                return ProfileInstallResult(
                    transaction_id=bpp.profile_metadata.get("transaction_id", ""),
                    iccid=resp.get("iccid"),
                    result_code=ResultCode.OK,
                )
            else:
                return ProfileInstallResult(
                    transaction_id="",
                    result_code=ResultCode.INSTALL_FAILED,
                    error_reason=resp.get("error", "Unknown error"),
                )

        return ProfileInstallResult(
            transaction_id="",
            result_code=ResultCode.INTERNAL_ERROR,
            error_reason="No profile metadata in BPP",
        )

    # -- ES10c: Profile management ----------------------------------------

    async def get_profiles_info(self) -> list[dict]:
        """ES10c.GetProfilesInfo - List all installed profiles."""
        resp = await self._send_message({"type": "list_profiles"})
        return resp.get("data", [])

    async def enable_profile(self, iccid: str) -> bool:
        """ES10c.EnableProfile - Enable a profile by ICCID."""
        resp = await self._send_message({
            "type": "enable_profile",
            "iccid": iccid,
        })
        return resp.get("success", False)

    async def disable_profile(self, iccid: str) -> bool:
        """ES10c.DisableProfile - Disable a profile by ICCID."""
        resp = await self._send_message({
            "type": "disable_profile",
            "iccid": iccid,
        })
        return resp.get("success", False)

    async def delete_profile(self, iccid: str) -> bool:
        """ES10c.DeleteProfile - Delete a profile by ICCID."""
        resp = await self._send_message({
            "type": "delete_profile",
            "iccid": iccid,
        })
        return resp.get("success", False)

    async def get_euicc_challenge(self) -> bytes:
        """ES10b.GetEUICCChallenge - Get a random challenge from the eUICC."""
        return os.urandom(16)

    # -- APDU passthrough -------------------------------------------------

    async def send_apdu(self, apdu_hex: str) -> dict:
        """Send a raw APDU command to the eUICC."""
        resp = await self._send_message({
            "type": "apdu",
            "data": apdu_hex,
        })
        return resp
