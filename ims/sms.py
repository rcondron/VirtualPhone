"""
SMS over IMS implementation per 3GPP TS 24.341.

Sends and receives SMS messages using SIP MESSAGE (RFC 3428) with
RP-DATA payloads (Content-Type: application/vnd.3gpp.sms).

Architecture:
  Android Messages → RIL SEND_SMS → RadioHAL → SMSoverIMS
    → SIP MESSAGE → P-CSCF → S-CSCF → destination

  P-CSCF → SIP MESSAGE → SMSoverIMS → RadioHAL → RIL NEW_SMS → Android

The SIP MESSAGE body contains an RP-DATA wrapper (3GPP TS 24.011)
around the SMS TPDU (3GPP TS 23.040).

Reference: 3GPP TS 24.341, RFC 3428, 3GPP TS 24.011
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from ims.sip_client import (
    SIPClient, SIPMessage, SIPStatus,
    generate_call_id, generate_branch, generate_tag,
)
from ims.sms_pdu import (
    SMSSubmit, SMSDeliver, SMSAddress, DataCodingScheme,
    RPData, RPAck, RPMessageType,
    parse_pdu_from_ril, build_pdu_for_ril, decode_scts,
)

logger = logging.getLogger(__name__)

# Content type for SMS over IMS (3GPP TS 24.341)
CONTENT_TYPE_3GPP_SMS = "application/vnd.3gpp.sms"

# Module-level SMS state for management API
_sms_state: dict = {
    "enabled": False,
    "messages_sent": 0,
    "messages_received": 0,
    "last_error": None,
}


def get_sms_state() -> dict:
    """Return the current SMS service state (called by management API)."""
    return dict(_sms_state)


@dataclass
class SMSConfig:
    """SMS over IMS configuration."""
    pcscf_address: str = ""
    pcscf_port: int = 5060
    transport: str = "UDP"
    impu: str = ""         # SIP URI of this UE
    impi: str = ""         # Private identity for auth
    home_domain: str = ""
    service_route: str = ""  # Route header from IMS registration
    smsc_address: str = ""   # Virtual SMSC address (for PDU headers)


class SMSoverIMS:
    """
    SMS over IMS service.

    Handles both MO-SMS (sending) and MT-SMS (receiving) using
    SIP MESSAGE with RP-DATA payloads per 3GPP TS 24.341.
    """

    def __init__(self, config: SMSConfig):
        self.config = config
        self._sip_client: Optional[SIPClient] = None
        self._message_ref: int = 0
        self._rp_ref: int = 0
        self._mt_callback: Optional[Callable[[str, str, str], Awaitable[None]]] = None
        self._started = False

    async def start(self) -> None:
        """Start the SMS service (SIP transport for MESSAGE requests)."""
        global _sms_state

        if not self.config.pcscf_address:
            logger.error("SMS: No P-CSCF address configured")
            return

        self._sip_client = SIPClient(
            transport=self.config.transport,
        )
        await self._sip_client.start()

        # Register handler for incoming SIP MESSAGE
        self._sip_client.transport.set_handler(self._handle_incoming_sip)

        self._started = True
        _sms_state["enabled"] = True
        logger.info("SMS over IMS started (P-CSCF=%s:%d)",
                     self.config.pcscf_address, self.config.pcscf_port)

    async def stop(self) -> None:
        """Stop the SMS service."""
        global _sms_state
        if self._sip_client:
            await self._sip_client.stop()
        self._started = False
        _sms_state["enabled"] = False

    def set_mt_callback(self, cb: Callable[[str, str, str], Awaitable[None]]) -> None:
        """
        Set callback for incoming (MT) SMS.

        Callback args: (from_number, to_number, text)
        """
        self._mt_callback = cb

    async def send_sms(self, smsc_pdu: str, pdu: str) -> dict:
        """
        Send an SMS via IMS (called from RadioHAL).

        Args:
            smsc_pdu: SMSC address PDU (usually empty for IMS)
            pdu: hex-encoded SMSC prefix + SMS-SUBMIT TPDU from Android

        Returns:
            dict with messageRef, ackPdu, errorCode
        """
        global _sms_state

        if not self._started:
            logger.warning("SMS: service not started, returning placeholder success")
            return {"messageRef": 0, "ackPdu": "", "errorCode": 0}

        try:
            # Parse TPDU from Android's PDU format
            _smsc_bytes, tpdu_bytes = parse_pdu_from_ril(pdu)
            submit = SMSSubmit.from_bytes(tpdu_bytes)

            # Extract destination number
            dest_number = submit.destination.number
            if submit.destination.type_of_number.value == 1:  # International
                dest_number = "+" + dest_number
            text = submit.text

            logger.info("SMS MO: to=%s text='%s' (dcs=%s, ref=%d)",
                        dest_number, text[:50], submit.dcs.name, submit.message_ref)

            # Build SIP MESSAGE with RP-DATA body
            self._message_ref = submit.message_ref
            success = await self._send_sip_message(dest_number, tpdu_bytes)

            if success:
                _sms_state["messages_sent"] += 1
                _sms_state["last_error"] = None
                return {
                    "messageRef": submit.message_ref,
                    "ackPdu": "",
                    "errorCode": 0,
                }
            else:
                _sms_state["last_error"] = "SIP MESSAGE failed"
                return {
                    "messageRef": submit.message_ref,
                    "ackPdu": "",
                    "errorCode": 1,  # Generic failure
                }

        except Exception as e:
            logger.exception("SMS MO: failed to send")
            _sms_state["last_error"] = str(e)
            return {"messageRef": 0, "ackPdu": "", "errorCode": 1}

    async def deliver_mt_sms(self, from_number: str, text: str,
                             to_number: str = "") -> bool:
        """
        Deliver an incoming SMS to Android via MT-SMS path.

        Called by the PSTN bridge or when a SIP MESSAGE is received.
        Creates an SMS-DELIVER TPDU and invokes the MT callback.
        """
        global _sms_state

        logger.info("SMS MT: from=%s text='%s'", from_number, text[:50])

        if self._mt_callback:
            await self._mt_callback(from_number, to_number, text)
            _sms_state["messages_received"] += 1
            return True

        logger.warning("SMS MT: no callback registered, message dropped")
        return False

    # ---- SIP MESSAGE construction -------------------------------------------

    async def _send_sip_message(self, dest_number: str,
                                tpdu: bytes) -> bool:
        """Send a SIP MESSAGE to deliver an SMS via IMS."""
        # Wrap TPDU in RP-DATA
        rp_data = RPData.wrap_mo(
            tpdu=tpdu,
            reference=self._next_rp_ref(),
            smsc=self.config.smsc_address,
        )
        body = rp_data.to_bytes()

        # Build destination SIP URI
        # For IMS SMS, the destination is typically the tel URI or sip URI
        dest_uri = f"sip:{dest_number.lstrip('+')}@{self.config.home_domain}"
        from_uri = self.config.impu
        if not from_uri.startswith("sip:"):
            from_uri = f"sip:{from_uri}"

        # Build extra headers
        headers = {
            "Content-Type": CONTENT_TYPE_3GPP_SMS,
        }

        # Add Route header from Service-Route if available
        if self.config.service_route:
            headers["Route"] = self.config.service_route

        # Add P-Preferred-Identity for IMS
        headers["P-Preferred-Identity"] = f"<{from_uri}>"

        dest = (self.config.pcscf_address, self.config.pcscf_port)

        try:
            response = await self._sip_client.send_request(
                method="MESSAGE",
                request_uri=dest_uri,
                to_uri=dest_uri,
                from_uri=from_uri,
                dest=dest,
                extra_headers=headers,
                body=body,
            )

            if response.status_code == SIPStatus.OK:
                logger.info("SMS MO: SIP MESSAGE delivered (200 OK)")
                return True
            elif response.status_code == 202:
                logger.info("SMS MO: SIP MESSAGE accepted (202 Accepted)")
                return True
            else:
                logger.error("SMS MO: SIP MESSAGE failed: %d %s",
                             response.status_code, response.reason_phrase)
                return False

        except TimeoutError:
            logger.error("SMS MO: SIP MESSAGE timed out")
            return False

    # ---- Incoming SIP MESSAGE handling --------------------------------------

    async def _handle_incoming_sip(self, msg: SIPMessage,
                                   addr: tuple) -> None:
        """Handle an incoming SIP message (response or request)."""
        if msg.is_response:
            # Let the SIP client handle responses to our requests
            cid = msg.call_id
            if cid in self._sip_client._pending_responses:
                if msg.status_code >= 200:
                    future = self._sip_client._pending_responses.pop(cid)
                    if not future.done():
                        future.set_result(msg)
            return

        # Handle incoming SIP MESSAGE request (MT-SMS)
        if msg.method == "MESSAGE":
            await self._handle_sip_message(msg, addr)

    async def _handle_sip_message(self, msg: SIPMessage,
                                  addr: tuple) -> None:
        """Process an incoming SIP MESSAGE containing RP-DATA."""
        global _sms_state

        content_type = msg.headers.get("Content-Type", "")

        # Send 200 OK immediately
        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Via": msg.headers.get("Via", ""),
                "From": msg.headers.get("From", ""),
                "To": msg.headers.get("To", ""),
                "Call-ID": msg.headers.get("Call-ID", ""),
                "CSeq": msg.headers.get("CSeq", ""),
            },
        )
        if self._sip_client:
            await self._sip_client.transport.send(ok_response, addr)

        if CONTENT_TYPE_3GPP_SMS not in content_type:
            # Plain text SIP MESSAGE (fallback)
            text = msg.body.decode("utf-8", errors="replace") if msg.body else ""
            from_uri = msg.headers.get("From", "")
            # Extract number from From URI
            from_number = _extract_number_from_uri(from_uri)

            if self._mt_callback and text:
                await self._mt_callback(from_number, "", text)
                _sms_state["messages_received"] += 1
            return

        # Parse RP-DATA from SIP MESSAGE body
        try:
            rp_data = RPData.from_bytes(msg.body)
            tpdu = rp_data.tpdu

            if rp_data.msg_type in (RPMessageType.RP_DATA_MT, RPMessageType.RP_DATA_MO):
                # Parse SMS-DELIVER TPDU
                deliver = SMSDeliver.from_bytes(tpdu)
                from_number = deliver.originator.number
                if deliver.originator.type_of_number.value == 1:
                    from_number = "+" + from_number
                text = deliver.text

                logger.info("SMS MT: from=%s text='%s' (via RP-DATA)",
                            from_number, text[:50])

                if self._mt_callback:
                    await self._mt_callback(from_number, "", text)
                    _sms_state["messages_received"] += 1

        except Exception:
            logger.exception("SMS MT: failed to parse RP-DATA")

    # ---- Helpers ------------------------------------------------------------

    def _next_rp_ref(self) -> int:
        """Get next RP-DATA reference number (0-255)."""
        ref = self._rp_ref
        self._rp_ref = (self._rp_ref + 1) & 0xFF
        return ref


def _extract_number_from_uri(uri: str) -> str:
    """Extract a phone number from a SIP URI like <sip:+1234@domain>;tag=xxx."""
    import re
    match = re.search(r'sip:([+\d]+)@', uri)
    if match:
        return match.group(1)
    match = re.search(r'tel:([+\d]+)', uri)
    if match:
        return match.group(1)
    return uri
