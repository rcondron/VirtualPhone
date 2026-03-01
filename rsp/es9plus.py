"""
ES9+ interface implementation (LPA ↔ SM-DP+).

The ES9+ interface is the HTTPS/JSON-based protocol between the Local
Profile Assistant (LPA) on the device and the SM-DP+ (Subscription
Manager - Data Preparation) server.

Protocol flow:
1. InitiateAuthentication → SM-DP+ returns server challenge + certificate
2. AuthenticateClient → SM-DP+ verifies eUICC, returns BPP preparation data
3. GetBoundProfilePackage → SM-DP+ returns the encrypted profile package
4. HandleNotification → LPA reports installation result

Reference: GSMA SGP.22 Section 5.6
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import ssl
from dataclasses import dataclass
from typing import Optional

import httpx

from rsp.asn1.rsp_definitions import (
    AuthenticateServerResponse,
    BoundProfilePackage,
    EUICCInfo1,
    ProfileInstallResult,
    ResultCode,
    ServerSigned1,
)

logger = logging.getLogger(__name__)

# SM-DP+ API endpoints (SGP.22 Section 5.6.1)
EP_INITIATE_AUTH = "/gsma/rsp2/es9plus/initiateAuthentication"
EP_AUTH_CLIENT = "/gsma/rsp2/es9plus/authenticateClient"
EP_GET_BPP = "/gsma/rsp2/es9plus/getBoundProfilePackage"
EP_HANDLE_NOTIFICATION = "/gsma/rsp2/es9plus/handleNotification"
EP_CANCEL_SESSION = "/gsma/rsp2/es9plus/cancelSession"


@dataclass
class ES9PlusConfig:
    """Configuration for ES9+ client."""
    smdp_address: str = ""
    tls_verify: bool = True
    timeout: float = 30.0
    client_cert: Optional[str] = None
    client_key: Optional[str] = None


class ES9PlusClient:
    """
    ES9+ client for communicating with SM-DP+ servers.

    Implements the device-side of the ES9+ interface per SGP.22.
    """

    def __init__(self, config: ES9PlusConfig):
        self.config = config
        self._http: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http is None:
            kwargs = {
                "timeout": self.config.timeout,
                "verify": self.config.tls_verify,
                "headers": {
                    "Content-Type": "application/json",
                    "User-Agent": "VirtualPhone-LPA/1.0 (GSMA-RSP)",
                    "X-Admin-Protocol": "gsma/rsp/v2.5.0",
                },
            }
            if self.config.client_cert and self.config.client_key:
                kwargs["cert"] = (self.config.client_cert, self.config.client_key)

            self._http = httpx.AsyncClient(**kwargs)
        return self._http

    async def initiate_authentication(
        self,
        euicc_challenge: bytes,
        euicc_info1: EUICCInfo1,
        smdp_address: str = "",
    ) -> AuthenticateServerResponse:
        """
        Step 1: InitiateAuthentication.

        Sends the eUICC challenge and info to the SM-DP+.
        The SM-DP+ responds with its challenge, certificate, and signed data.

        Args:
            euicc_challenge: 16-byte random challenge from the eUICC.
            euicc_info1: eUICC information structure.
            smdp_address: SM-DP+ server address (overrides config).

        Returns:
            AuthenticateServerResponse with server challenge and certificate.
        """
        address = smdp_address or self.config.smdp_address
        if not address:
            raise ValueError("SM-DP+ address not configured")

        url = f"https://{address}{EP_INITIATE_AUTH}"

        payload = {
            "euiccChallenge": base64.b64encode(euicc_challenge).decode(),
            "euiccInfo1": {
                "svn": base64.b64encode(euicc_info1.svn).decode(),
            },
            "smdpAddress": address,
        }

        client = await self._get_client()
        logger.info("ES9+ InitiateAuthentication → %s", address)

        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

        # Parse response
        header = data.get("header", {})
        transaction_id = header.get("functionExecutionStatus", {}).get(
            "status", {}).get("subjectCode", data.get("transactionId", ""))

        server_signed1 = data.get("serverSigned1", "")
        server_sig1 = data.get("serverSignature1", "")
        server_cert = data.get("serverCertificate", "")

        result = AuthenticateServerResponse(
            transaction_id=data.get("transactionId", ""),
            server_signed1=ServerSigned1(
                transaction_id=data.get("transactionId", ""),
                euicc_challenge=euicc_challenge,
                server_address=address,
                server_challenge=base64.b64decode(data.get("serverChallenge", "")),
            ),
            server_signature1=base64.b64decode(server_sig1) if server_sig1 else b"",
            euicc_ci_pk_id=base64.b64decode(
                data.get("euiccCiPKIdToBeUsed", "")
            ) if data.get("euiccCiPKIdToBeUsed") else b"",
            server_certificate=base64.b64decode(server_cert) if server_cert else b"",
        )

        logger.info("ES9+ InitiateAuthentication OK, txn=%s", result.transaction_id)
        return result

    async def authenticate_client(
        self,
        transaction_id: str,
        authenticate_server_response: bytes,
        smdp_address: str = "",
    ) -> dict:
        """
        Step 2: AuthenticateClient.

        Sends the eUICC's authentication response to the SM-DP+.
        The SM-DP+ verifies the eUICC and prepares the profile.

        Returns:
            Profile metadata and preparation data.
        """
        address = smdp_address or self.config.smdp_address
        url = f"https://{address}{EP_AUTH_CLIENT}"

        payload = {
            "transactionId": transaction_id,
            "authenticateServerResponse": base64.b64encode(
                authenticate_server_response
            ).decode(),
        }

        client = await self._get_client()
        logger.info("ES9+ AuthenticateClient → txn=%s", transaction_id)

        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

        logger.info("ES9+ AuthenticateClient OK")
        return data

    async def get_bound_profile_package(
        self,
        transaction_id: str,
        prepare_download_response: bytes,
        smdp_address: str = "",
    ) -> BoundProfilePackage:
        """
        Step 3: GetBoundProfilePackage.

        Requests the actual encrypted profile package from the SM-DP+.

        Returns:
            BoundProfilePackage containing the encrypted eSIM profile.
        """
        address = smdp_address or self.config.smdp_address
        url = f"https://{address}{EP_GET_BPP}"

        payload = {
            "transactionId": transaction_id,
            "prepareDownloadResponse": base64.b64encode(
                prepare_download_response
            ).decode(),
        }

        client = await self._get_client()
        logger.info("ES9+ GetBoundProfilePackage → txn=%s", transaction_id)

        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

        bpp = BoundProfilePackage(
            initialise_secure_channel=base64.b64decode(
                data.get("initialiseSecureChannelRequest", "")
            ),
            first_sequence_87=base64.b64decode(
                data.get("firstSequenceOf87", "")
            ),
            sequence_88=base64.b64decode(
                data.get("sequenceOf88", "")
            ),
            profile_metadata=data.get("profileMetadata"),
        )

        logger.info("ES9+ GetBoundProfilePackage OK")
        return bpp

    async def handle_notification(
        self,
        pending_notification: bytes,
        smdp_address: str = "",
    ) -> None:
        """
        Step 4: HandleNotification.

        Reports the result of a profile download/installation to the SM-DP+.
        """
        address = smdp_address or self.config.smdp_address
        url = f"https://{address}{EP_HANDLE_NOTIFICATION}"

        payload = {
            "pendingNotification": base64.b64encode(
                pending_notification
            ).decode(),
        }

        client = await self._get_client()
        logger.info("ES9+ HandleNotification → %s", address)

        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        logger.info("ES9+ HandleNotification OK")

    async def cancel_session(
        self,
        transaction_id: str,
        reason: int = 0,
        smdp_address: str = "",
    ) -> None:
        """Cancel an ongoing RSP session."""
        address = smdp_address or self.config.smdp_address
        url = f"https://{address}{EP_CANCEL_SESSION}"

        payload = {
            "transactionId": transaction_id,
            "cancelSessionResponse": {
                "transactionId": transaction_id,
                "cancelSessionReason": reason,
            },
        }

        client = await self._get_client()
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        logger.info("ES9+ CancelSession OK, txn=%s", transaction_id)

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http:
            await self._http.aclose()
            self._http = None
