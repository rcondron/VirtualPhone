"""
Local Profile Assistant (LPA) implementation.

The LPA orchestrates the RSP profile download process by:
1. Communicating with the eUICC via ES10 (local interface)
2. Communicating with the SM-DP+ via ES9+ (network interface)
3. Managing profile lifecycle (enable, disable, delete)
4. Handling user confirmations

The LPA consists of three components:
- LPAd (LPA in device) - this implementation
- LPAe (LPA in eUICC) - handled by the eUICC daemon
- LUI (Local User Interface) - exposed via the management API

Reference: GSMA SGP.22 Section 3.1.1
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from rsp.es9plus import ES9PlusClient, ES9PlusConfig
from rsp.es10 import ES10Client

logger = logging.getLogger(__name__)


class LPAState(Enum):
    IDLE = "idle"
    AUTHENTICATING = "authenticating"
    DOWNLOADING = "downloading"
    INSTALLING = "installing"
    ERROR = "error"


@dataclass
class ActivationCode:
    """
    Parsed SM-DP+ activation code (SGP.22 Section 4.1).

    Format: 1$<SM-DP+ address>$<matching ID>[$<OID>]
    Example: 1$smdp.example.com$ABCDEF1234567890
    """
    smdp_address: str
    matching_id: str = ""
    oid: str = ""

    @classmethod
    def parse(cls, code: str) -> ActivationCode:
        """Parse an activation code string."""
        parts = code.strip().split("$")
        if len(parts) < 2 or parts[0] != "1":
            raise ValueError(f"Invalid activation code format: {code}")
        return cls(
            smdp_address=parts[1],
            matching_id=parts[2] if len(parts) > 2 else "",
            oid=parts[3] if len(parts) > 3 else "",
        )


class LPA:
    """
    Local Profile Assistant - orchestrates eSIM profile provisioning.

    Usage:
        lpa = LPA()
        await lpa.initialize()

        # Download a profile using an activation code
        result = await lpa.download_profile("1$smdp.example.com$MATCHINGID123")

        # Manage profiles
        profiles = await lpa.list_profiles()
        await lpa.enable_profile(iccid="8901...")
    """

    def __init__(
        self,
        es10_socket: str = "/run/vphone/euicc.sock",
        smdp_address: str = "",
    ):
        self.es10 = ES10Client(socket_path=es10_socket)
        self.es9plus_config = ES9PlusConfig(smdp_address=smdp_address)
        self.state = LPAState.IDLE
        self._current_transaction: Optional[str] = None

    async def initialize(self) -> dict:
        """Initialize the LPA and verify eUICC connectivity."""
        logger.info("Initializing LPA...")
        info = await self.es10.get_euicc_info2()
        eid = info.get("eid", "unknown")
        logger.info("LPA initialized. EID=%s, profiles=%d", eid, info.get("installed_profiles", 0))
        return info

    async def download_profile(
        self,
        activation_code: str,
        confirmation_code: Optional[str] = None,
    ) -> dict:
        """
        Download and install an eSIM profile using an activation code.

        Full RSP profile download flow:
        1. Parse activation code to get SM-DP+ address
        2. ES10b: GetEUICCChallenge
        3. ES9+: InitiateAuthentication
        4. ES10b: AuthenticateServer (verify SM-DP+ certificate)
        5. ES9+: AuthenticateClient (send eUICC auth response)
        6. ES10b: PrepareDownload
        7. ES9+: GetBoundProfilePackage
        8. ES10b: LoadBoundProfilePackage
        9. ES9+: HandleNotification (report result)

        Args:
            activation_code: SM-DP+ activation code (1$address$matchingId).
            confirmation_code: Optional confirmation code for protected profiles.

        Returns:
            Dictionary with download result.
        """
        try:
            self.state = LPAState.AUTHENTICATING
            ac = ActivationCode.parse(activation_code)
            logger.info("Starting profile download from %s", ac.smdp_address)

            # Create ES9+ client for this SM-DP+
            config = ES9PlusConfig(smdp_address=ac.smdp_address)
            es9 = ES9PlusClient(config)

            try:
                # Step 1: Get eUICC challenge
                euicc_challenge = await self.es10.get_euicc_challenge()
                euicc_info1 = await self.es10.get_euicc_info1()

                # Step 2: InitiateAuthentication with SM-DP+
                auth_resp = await es9.initiate_authentication(
                    euicc_challenge=euicc_challenge,
                    euicc_info1=euicc_info1,
                    smdp_address=ac.smdp_address,
                )
                self._current_transaction = auth_resp.transaction_id

                # Step 3: Authenticate server (verify SM-DP+ certificate on eUICC)
                # In a full implementation, the eUICC verifies the server cert chain
                # and returns an AuthenticateServerResponse

                # Step 4: AuthenticateClient with SM-DP+
                self.state = LPAState.DOWNLOADING
                auth_client_resp = await es9.authenticate_client(
                    transaction_id=auth_resp.transaction_id,
                    authenticate_server_response=euicc_challenge,  # Simplified
                    smdp_address=ac.smdp_address,
                )

                # Step 5: PrepareDownload on eUICC
                prepare_resp = await self.es10.prepare_download(
                    transaction_id=auth_resp.transaction_id,
                    hash_cc=None,
                    smdp_signed2=b"",
                    smdp_signature2=b"",
                    smdp_certificate=auth_resp.server_certificate,
                )

                # Step 6: GetBoundProfilePackage from SM-DP+
                bpp = await es9.get_bound_profile_package(
                    transaction_id=auth_resp.transaction_id,
                    prepare_download_response=b"",  # Simplified
                    smdp_address=ac.smdp_address,
                )

                # Step 7: Load the profile onto the eUICC
                self.state = LPAState.INSTALLING
                install_result = await self.es10.load_bound_profile_package(bpp)

                # Step 8: Notify SM-DP+ of result
                await es9.handle_notification(
                    pending_notification=json.dumps({
                        "transaction_id": auth_resp.transaction_id,
                        "result": install_result.result_code.value,
                        "iccid": install_result.iccid,
                    }).encode(),
                    smdp_address=ac.smdp_address,
                )

                self.state = LPAState.IDLE
                self._current_transaction = None

                return {
                    "success": install_result.result_code == 0,
                    "iccid": install_result.iccid,
                    "result_code": install_result.result_code.value,
                }

            finally:
                await es9.close()

        except Exception as e:
            self.state = LPAState.ERROR
            logger.exception("Profile download failed")
            return {
                "success": False,
                "error": str(e),
            }

    async def install_profile_direct(self, profile_data: dict) -> dict:
        """
        Install a profile directly (bypassing SM-DP+).

        For testing/development: installs profile data directly into
        the eUICC without going through the RSP flow.

        Args:
            profile_data: Dictionary with ICCID, IMSI, Ki, OPc, etc.
        """
        logger.info("Direct profile install: ICCID=%s", profile_data.get("iccid"))

        from rsp.asn1.rsp_definitions import BoundProfilePackage

        bpp = BoundProfilePackage(profile_metadata=profile_data)
        result = await self.es10.load_bound_profile_package(bpp)

        return {
            "success": result.result_code.value == 0,
            "iccid": result.iccid,
            "result_code": result.result_code.value,
        }

    async def list_profiles(self) -> list[dict]:
        """List all profiles installed on the eUICC."""
        return await self.es10.get_profiles_info()

    async def enable_profile(self, iccid: str) -> bool:
        """Enable a profile by ICCID."""
        logger.info("Enabling profile ICCID=%s", iccid)
        return await self.es10.enable_profile(iccid)

    async def disable_profile(self, iccid: str) -> bool:
        """Disable a profile by ICCID."""
        logger.info("Disabling profile ICCID=%s", iccid)
        return await self.es10.disable_profile(iccid)

    async def delete_profile(self, iccid: str) -> bool:
        """Delete a profile by ICCID."""
        logger.info("Deleting profile ICCID=%s", iccid)
        return await self.es10.delete_profile(iccid)

    async def get_eid(self) -> str:
        """Get the eUICC EID."""
        return await self.es10.get_eid()

    async def get_euicc_info(self) -> dict:
        """Get eUICC information."""
        return await self.es10.get_euicc_info2()


# Needed for json import above in download_profile
import json
