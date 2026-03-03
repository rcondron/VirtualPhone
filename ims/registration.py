"""
IMS Registration implementation.

Handles the SIP REGISTER procedure for IMS as defined in 3GPP TS 24.229.
The registration flow:
1. Send initial REGISTER (no credentials)
2. Receive 401 Unauthorized with WWW-Authenticate (contains AKA challenge)
3. Run EAP-AKA/Milenage to compute response
4. Send REGISTER with Authorization header
5. Receive 200 OK (registered)

For VoWiFi, registration happens after the IPsec tunnel is established.
For VoLTE, registration uses IPsec transport mode (SIP over IPsec).

Reference: 3GPP TS 24.229, 3GPP TS 33.203
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from euicc.crypto.milenage import Milenage
from ims.sip_client import SIPClient, SIPMessage, SIPStatus, generate_call_id

logger = logging.getLogger(__name__)


class IMSRegState(Enum):
    NOT_REGISTERED = "not_registered"
    REGISTERING = "registering"
    REGISTERED = "registered"
    DEREGISTERING = "deregistering"
    FAILED = "failed"


@dataclass
class IMSCredentials:
    """IMS authentication credentials from the ISIM/USIM."""
    impi: str          # IMS Private Identity (e.g., 001010123456789@ims.domain)
    impu: str          # IMS Public Identity (e.g., sip:001010123456789@ims.domain)
    home_domain: str   # IMS home domain
    ki: bytes          # Authentication key
    opc: bytes         # Operator variant key
    sqn: int = 0       # AKA sequence number


@dataclass
class IMSConfig:
    """IMS registration configuration."""
    pcscf_address: str = ""       # P-CSCF address (proxy)
    pcscf_port: int = 5060
    transport: str = "UDP"        # UDP, TCP, or TLS
    registration_expiry: int = 3600  # seconds
    realm: str = ""               # SIP authentication realm
    use_ipsec: bool = False       # IPsec transport mode (VoLTE)


class IMSRegistration:
    """
    IMS Registration handler.

    Manages the SIP REGISTER procedure with AKA authentication.
    """

    def __init__(self, credentials: IMSCredentials, config: IMSConfig):
        self.creds = credentials
        self.config = config
        self.state = IMSRegState.NOT_REGISTERED
        self._sip_client: Optional[SIPClient] = None
        self._registration_timer: Optional[asyncio.Task] = None
        self._call_id = generate_call_id()
        self._cseq = 1
        self.service_route: Optional[str] = None

    async def register(self) -> bool:
        """
        Perform IMS registration via SIP REGISTER.

        Returns True if registration succeeds.
        """
        if not self.config.pcscf_address:
            logger.error("No P-CSCF address configured")
            self.state = IMSRegState.FAILED
            return False

        self.state = IMSRegState.REGISTERING
        logger.info(
            "Starting IMS registration: IMPI=%s → P-CSCF=%s:%d",
            self.creds.impi, self.config.pcscf_address, self.config.pcscf_port,
        )

        # Create SIP client
        self._sip_client = SIPClient(transport=self.config.transport)
        await self._sip_client.start()

        try:
            # Step 1: Initial REGISTER (no auth)
            response = await self._send_register()

            if response.status_code == SIPStatus.UNAUTHORIZED:
                # Step 2: Extract AKA challenge from 401 response
                www_auth = response.headers.get("WWW-Authenticate", "")
                logger.debug("Got 401 challenge: %s", www_auth[:80])

                # Step 3: Compute AKA response
                auth_header = self._compute_aka_response(www_auth)
                if auth_header is None:
                    logger.error("Failed to compute AKA response")
                    self.state = IMSRegState.FAILED
                    return False

                # Step 4: Re-REGISTER with Authorization
                response = await self._send_register(
                    extra_headers={"Authorization": auth_header}
                )

            if response.status_code == SIPStatus.OK:
                self.state = IMSRegState.REGISTERED
                logger.info("IMS registration successful")

                # Extract service-route and other headers
                self._process_200ok(response)

                # Schedule re-registration
                expiry = self.config.registration_expiry
                contact = response.headers.get("Contact", "")
                if "expires=" in contact:
                    try:
                        expiry = int(contact.split("expires=")[1].split(";")[0].split(",")[0])
                    except ValueError:
                        pass

                self._schedule_reregistration(expiry)
                return True
            else:
                logger.error(
                    "IMS registration failed: %d %s",
                    response.status_code, response.reason_phrase,
                )
                self.state = IMSRegState.FAILED
                return False

        except Exception:
            logger.exception("IMS registration error")
            self.state = IMSRegState.FAILED
            return False

    async def deregister(self) -> bool:
        """Deregister from IMS."""
        if self.state != IMSRegState.REGISTERED:
            return True

        self.state = IMSRegState.DEREGISTERING

        if self._registration_timer:
            self._registration_timer.cancel()

        try:
            response = await self._send_register(
                extra_headers={"Expires": "0", "Contact": "*"}
            )
            self.state = IMSRegState.NOT_REGISTERED
            logger.info("IMS deregistration successful")
            return True
        except Exception:
            logger.exception("IMS deregistration error")
            self.state = IMSRegState.FAILED
            return False
        finally:
            if self._sip_client:
                await self._sip_client.stop()

    async def _send_register(
        self,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> SIPMessage:
        """Send a SIP REGISTER request."""
        request_uri = f"sip:{self.creds.home_domain}"
        dest = (self.config.pcscf_address, self.config.pcscf_port)

        headers = {
            "Contact": f"<sip:{self.creds.impi}>",
            "Expires": str(self.config.registration_expiry),
            "Allow": "INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, SUBSCRIBE, MESSAGE",
            "Supported": "path, outbound, gruu, sec-agree",
        }

        # Add security headers for IPsec (3GPP TS 33.203)
        if self.config.use_ipsec:
            spi_c = int.from_bytes(os.urandom(4), "big")
            spi_s = int.from_bytes(os.urandom(4), "big")
            headers["Security-Client"] = (
                f"ipsec-3gpp; alg=hmac-sha-1-96; "
                f"spi-c={spi_c}; spi-s={spi_s}; "
                f"port-c=5060; port-s=5060"
            )

        if extra_headers:
            headers.update(extra_headers)

        return await self._sip_client.send_request(
            method="REGISTER",
            request_uri=request_uri,
            to_uri=self.creds.impu,
            from_uri=self.creds.impu,
            dest=dest,
            extra_headers=headers,
            call_id=self._call_id,
        )

    def _compute_aka_response(self, www_authenticate: str) -> Optional[str]:
        """
        Compute AKA authentication response from a 401 challenge.

        The WWW-Authenticate header contains:
        - nonce: base64(RAND || AUTN || server-specific)
        - algorithm: AKAv1-MD5

        We run Milenage to compute RES, CK, IK and derive the response.
        """
        # Parse WWW-Authenticate
        params = {}
        auth_part = www_authenticate.replace("Digest ", "")
        for part in auth_part.split(","):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                params[key.strip()] = val.strip().strip('"')

        nonce = params.get("nonce", "")
        realm = params.get("realm", self.creds.home_domain)
        algorithm = params.get("algorithm", "AKAv1-MD5")

        if not nonce:
            logger.error("No nonce in WWW-Authenticate")
            return None

        try:
            # Decode nonce to extract RAND and AUTN
            nonce_bytes = base64.b64decode(nonce)
            if len(nonce_bytes) < 32:
                logger.error("Nonce too short for AKA: %d bytes", len(nonce_bytes))
                return None

            rand = nonce_bytes[:16]
            autn = nonce_bytes[16:32]

            # Run Milenage
            mil = Milenage(self.creds.ki, self.creds.opc)
            result = mil.authenticate(rand, autn, self.creds.sqn)

            if result is None:
                logger.warning("AKA authentication failed (sync issue)")
                return None

            res, ck, ik = result
            self.creds.sqn += 1

            # For IMS AKAv1-MD5, the "password" is RES
            # The response is computed as standard SIP Digest but with RES as password
            password = res.hex()

            # Build Authorization header
            uri = f"sip:{self.creds.home_domain}"
            return self._sip_client.build_auth_header(
                www_authenticate=www_authenticate,
                method="REGISTER",
                uri=uri,
                username=self.creds.impi,
                password=password,
            )

        except Exception:
            logger.exception("AKA response computation failed")
            return None

    def _process_200ok(self, response: SIPMessage) -> None:
        """Process a 200 OK registration response."""
        # Extract Service-Route header for future requests (used in INVITE Route header)
        service_route = response.headers.get("Service-Route")
        if service_route:
            self.service_route = service_route
            logger.info("Service-Route: %s", service_route)

        # Extract P-Associated-URI (registered public identities)
        p_assoc = response.headers.get("P-Associated-URI")
        if p_assoc:
            logger.info("P-Associated-URI: %s", p_assoc)

    def _schedule_reregistration(self, expiry: int) -> None:
        """Schedule a re-registration before expiry."""
        # Re-register at 90% of expiry time
        delay = max(60, int(expiry * 0.9))
        logger.info("Re-registration scheduled in %d seconds", delay)

        async def _reregister():
            await asyncio.sleep(delay)
            if self.state == IMSRegState.REGISTERED:
                logger.info("Re-registration timer fired")
                await self.register()

        self._registration_timer = asyncio.create_task(_reregister())
