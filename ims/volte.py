"""
VoLTE (Voice over LTE) call management.

Handles VoLTE voice calls using SIP INVITE/BYE/ACK signaling
through the IMS core. Media is carried over RTP.

Call flow (MO - Mobile Originated):
  Android DIAL → RadioHAL → VoLTECallManager.initiate_call()
    → SIP INVITE (with SDP offer) → P-CSCF → S-CSCF → callee
  ← 100 Trying ← 180 Ringing (update state to ALERTING)
  ← 200 OK (with SDP answer) → ACK → state = ACTIVE

Call flow (MT - Mobile Terminated):
  SIP INVITE → VoLTECallManager._handle_incoming_invite()
    → RadioHAL.incoming_call() → Android ring
  Android ANSWER → RadioHAL.answer() → VoLTECallManager.answer_call()
    → 200 OK (with SDP answer) → state = ACTIVE

Call termination:
  Android HANGUP → RadioHAL.hangup() → VoLTECallManager.hangup_call()
    → SIP BYE → P-CSCF → callee
  ← 200 OK → call removed

Key differences from VoWiFi:
- No ePDG tunnel needed (direct LTE bearer)
- IPsec transport mode (not tunnel mode)
- P-CSCF discovered via PCO in PDN connection
- Dedicated EPS bearers for voice (QCI=1)

Reference: 3GPP TS 24.229, 3GPP TS 23.228, RFC 3261
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Awaitable, TYPE_CHECKING

from ims.registration import IMSRegistration, IMSCredentials, IMSConfig, IMSRegState
from ims.sip_client import (
    SIPClient, SIPMessage, SIPStatus,
    generate_call_id, generate_branch, generate_tag,
)
from ims.media import MediaSession, parse_remote_rtp_address, parse_payload_type

if TYPE_CHECKING:
    from hal.radio_hal import RadioHAL

logger = logging.getLogger(__name__)


@dataclass
class VoLTEConfig:
    """VoLTE-specific configuration."""
    pcscf_address: str = ""
    pcscf_port: int = 5060
    transport: str = "UDP"
    use_ipsec_transport: bool = True  # IPsec transport mode for SIP
    # QoS parameters
    qci: int = 1                # QoS Class Identifier (1 = conversational voice)
    gbr_ul: int = 41000         # Guaranteed bit rate uplink (bps)
    gbr_dl: int = 41000         # Guaranteed bit rate downlink (bps)
    # Codec preferences
    codec_priority: list[str] = None
    # IMS identities
    impu: str = ""
    impi: str = ""
    home_domain: str = ""
    service_route: str = ""
    # Local media
    local_ip: str = ""
    rtp_port_base: int = 50000

    def __post_init__(self):
        if self.codec_priority is None:
            self.codec_priority = ["AMR-WB", "AMR-NB", "EVS"]


class VoLTECallState(Enum):
    """State of an individual VoLTE call."""
    INITIATING = "initiating"
    RINGING_OUT = "ringing_out"   # MO: callee is ringing
    RINGING_IN = "ringing_in"     # MT: we are ringing
    ACTIVE = "active"
    HELD = "held"
    TERMINATING = "terminating"
    ENDED = "ended"


# Module-level call state for management API
_volte_state: dict = {
    "enabled": False,
    "active_calls": 0,
    "total_calls": 0,
    "codec": None,
}


def get_volte_state() -> dict:
    """Return VoLTE call state for the management API."""
    return dict(_volte_state)


@dataclass
class VoLTECall:
    """A single VoLTE call session."""
    sip_call_id: str = ""
    radio_call_index: int = 0  # Matches RadioHAL VoiceCall.index
    state: VoLTECallState = VoLTECallState.INITIATING
    direction: str = "MO"       # "MO" or "MT"
    remote_number: str = ""
    remote_uri: str = ""
    local_sdp: str = ""
    remote_sdp: str = ""
    rtp_port: int = 0
    codec: str = ""
    media_session: Optional[MediaSession] = field(default=None, repr=False)


class VoLTECallManager:
    """
    VoLTE call manager.

    Manages SIP call signaling (INVITE/BYE/ACK/CANCEL) and tracks
    active call sessions. Bridges between RadioHAL call requests
    and SIP signaling via the IMS P-CSCF.
    """

    def __init__(self, config: VoLTEConfig):
        self.config = config
        self._sip_client: Optional[SIPClient] = None
        self._radio_hal: Optional[RadioHAL] = None
        self._calls: dict[str, VoLTECall] = {}  # keyed by sip_call_id
        self._rtp_port_next: int = config.rtp_port_base
        self._started = False

    def set_radio_hal(self, hal: RadioHAL) -> None:
        """Set the RadioHAL for call state updates."""
        self._radio_hal = hal

    async def start(self) -> None:
        """Start the call manager (SIP transport)."""
        global _volte_state

        if not self.config.pcscf_address:
            logger.error("VoLTE: No P-CSCF address configured")
            return

        self._sip_client = SIPClient(
            transport=self.config.transport,
        )
        await self._sip_client.start()

        # Register handler for incoming SIP requests (INVITE, BYE, CANCEL)
        self._sip_client.transport.set_handler(self._handle_incoming_sip)

        self._started = True
        _volte_state["enabled"] = True
        logger.info("VoLTE call manager started (P-CSCF=%s:%d)",
                     self.config.pcscf_address, self.config.pcscf_port)

    async def stop(self) -> None:
        """Stop the call manager."""
        global _volte_state
        # Hangup all active calls
        for call in list(self._calls.values()):
            if call.state in (VoLTECallState.ACTIVE, VoLTECallState.RINGING_OUT):
                await self.hangup_call(call.sip_call_id)
        if self._sip_client:
            await self._sip_client.stop()
        self._started = False
        _volte_state["enabled"] = False

    # ---- MO Call (Outgoing) -------------------------------------------------

    async def initiate_call(self, number: str,
                            radio_call_index: int) -> Optional[str]:
        """
        Initiate an outgoing VoLTE call.

        Sends SIP INVITE to the remote party via P-CSCF.
        Returns the SIP Call-ID on success, None on failure.
        """
        global _volte_state

        if not self._started:
            logger.error("VoLTE: call manager not started")
            return None

        # Allocate RTP port
        rtp_port = self._allocate_rtp_port()
        local_ip = self.config.local_ip or "10.45.0.2"

        # Build SDP offer
        sdp = build_sdp_offer(
            local_ip, rtp_port,
            self.config.codec_priority,
        )

        # Build SIP URIs
        call_id = generate_call_id()
        dest_number = number.lstrip("+")
        dest_uri = f"sip:{dest_number}@{self.config.home_domain}"
        from_uri = self.config.impu
        if not from_uri.startswith("sip:"):
            from_uri = f"sip:{from_uri}"

        # Create call session
        call = VoLTECall(
            sip_call_id=call_id,
            radio_call_index=radio_call_index,
            state=VoLTECallState.INITIATING,
            direction="MO",
            remote_number=number,
            remote_uri=dest_uri,
            local_sdp=sdp,
            rtp_port=rtp_port,
        )
        self._calls[call_id] = call

        # Build headers
        headers = {
            "Content-Type": "application/sdp",
            "Allow": "INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE",
            "Supported": "100rel, timer, precondition",
            "P-Preferred-Identity": f"<{from_uri}>",
        }
        if self.config.service_route:
            headers["Route"] = self.config.service_route

        dest = (self.config.pcscf_address, self.config.pcscf_port)

        try:
            logger.info("VoLTE MO: INVITE → %s (call_id=%s)", dest_uri, call_id)
            response = await self._sip_client.send_request(
                method="INVITE",
                request_uri=dest_uri,
                to_uri=dest_uri,
                from_uri=from_uri,
                dest=dest,
                extra_headers=headers,
                body=sdp.encode(),
                call_id=call_id,
            )

            if response.status_code == SIPStatus.OK:
                call.state = VoLTECallState.ACTIVE
                call.remote_sdp = response.body.decode("utf-8", errors="replace")
                call.codec = _extract_codec_from_sdp(call.remote_sdp)

                # Send ACK
                await self._send_ack(call, dest)

                # Update RadioHAL
                if self._radio_hal:
                    from hal.radio_hal import CallState
                    await self._radio_hal.update_call_state(
                        radio_call_index, CallState.ACTIVE
                    )

                _volte_state["active_calls"] = len([
                    c for c in self._calls.values()
                    if c.state == VoLTECallState.ACTIVE
                ])
                _volte_state["total_calls"] += 1
                _volte_state["codec"] = call.codec

                # Start media session
                await self._start_media(call)

                logger.info("VoLTE MO: call active (codec=%s, rtp=%d)",
                            call.codec, rtp_port)
                return call_id

            else:
                logger.error("VoLTE MO: INVITE failed: %d %s",
                             response.status_code, response.reason_phrase)
                del self._calls[call_id]
                return None

        except TimeoutError:
            logger.error("VoLTE MO: INVITE timed out")
            del self._calls[call_id]
            return None

    # ---- MT Call (Incoming) -------------------------------------------------

    async def _handle_incoming_invite(self, msg: SIPMessage,
                                      addr: tuple) -> None:
        """Handle an incoming SIP INVITE (MT call)."""
        call_id = msg.call_id
        from_uri = msg.headers.get("From", "")
        from_number = _extract_number_from_uri(from_uri)

        logger.info("VoLTE MT: INVITE from %s (call_id=%s)", from_number, call_id)

        # Send 180 Ringing
        ringing = SIPMessage(
            status_code=180,
            reason_phrase="Ringing",
            headers={
                "Via": msg.headers.get("Via", ""),
                "From": msg.headers.get("From", ""),
                "To": msg.headers.get("To", ""),
                "Call-ID": call_id,
                "CSeq": msg.headers.get("CSeq", ""),
            },
        )
        if self._sip_client:
            await self._sip_client.transport.send(ringing, addr)

        # Allocate RTP port and prepare SDP
        rtp_port = self._allocate_rtp_port()
        local_ip = self.config.local_ip or "10.45.0.2"
        local_sdp = build_sdp_offer(
            local_ip, rtp_port,
            self.config.codec_priority,
        )

        # Create call session
        call = VoLTECall(
            sip_call_id=call_id,
            state=VoLTECallState.RINGING_IN,
            direction="MT",
            remote_number=from_number,
            remote_uri=from_uri,
            remote_sdp=msg.body.decode("utf-8", errors="replace") if msg.body else "",
            local_sdp=local_sdp,
            rtp_port=rtp_port,
        )
        self._calls[call_id] = call

        # Store the incoming INVITE details for answer
        call._invite_msg = msg
        call._invite_addr = addr

        # Notify RadioHAL of incoming call
        if self._radio_hal:
            await self._radio_hal.incoming_call(from_number, call_id)
            call.radio_call_index = self._radio_hal.voice_calls[-1].index

    async def answer_call(self, sip_call_id: str) -> bool:
        """
        Answer an incoming call.

        Sends 200 OK with SDP answer to the caller.
        Called by RadioHAL when Android answers.
        """
        global _volte_state

        call = self._calls.get(sip_call_id)
        if not call or call.state != VoLTECallState.RINGING_IN:
            logger.warning("VoLTE: cannot answer call %s (not ringing)", sip_call_id)
            return False

        # Build 200 OK with SDP
        invite_msg = getattr(call, "_invite_msg", None)
        invite_addr = getattr(call, "_invite_addr", None)

        if not invite_msg or not self._sip_client:
            return False

        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Via": invite_msg.headers.get("Via", ""),
                "From": invite_msg.headers.get("From", ""),
                "To": invite_msg.headers.get("To", ""),
                "Call-ID": sip_call_id,
                "CSeq": invite_msg.headers.get("CSeq", ""),
                "Contact": f"<sip:{self.config.impu}>",
                "Content-Type": "application/sdp",
            },
            body=call.local_sdp.encode(),
        )
        await self._sip_client.transport.send(ok_response, invite_addr)

        call.state = VoLTECallState.ACTIVE
        call.codec = _extract_codec_from_sdp(call.remote_sdp)

        _volte_state["active_calls"] = len([
            c for c in self._calls.values()
            if c.state == VoLTECallState.ACTIVE
        ])
        _volte_state["total_calls"] += 1
        _volte_state["codec"] = call.codec

        # Start media session
        await self._start_media(call)

        logger.info("VoLTE MT: call answered (codec=%s)", call.codec)
        return True

    # ---- Hangup / BYE -------------------------------------------------------

    async def hangup_call(self, sip_call_id: str) -> bool:
        """
        Hang up a call by sending SIP BYE.

        Called by RadioHAL when Android hangs up.
        """
        global _volte_state

        call = self._calls.pop(sip_call_id, None)
        if not call:
            return False

        # Stop media session
        await self._stop_media(call)

        if not self._sip_client or not self._started:
            return False

        call.state = VoLTECallState.TERMINATING

        from_uri = self.config.impu
        if not from_uri.startswith("sip:"):
            from_uri = f"sip:{from_uri}"

        dest = (self.config.pcscf_address, self.config.pcscf_port)

        headers = {}
        if self.config.service_route:
            headers["Route"] = self.config.service_route

        try:
            logger.info("VoLTE: BYE → %s (call_id=%s)", call.remote_uri, sip_call_id)
            response = await self._sip_client.send_request(
                method="BYE",
                request_uri=call.remote_uri,
                to_uri=call.remote_uri,
                from_uri=from_uri,
                dest=dest,
                extra_headers=headers,
                call_id=sip_call_id,
            )

            logger.info("VoLTE: BYE response: %d", response.status_code)

        except TimeoutError:
            logger.warning("VoLTE: BYE timed out for %s", sip_call_id)

        _volte_state["active_calls"] = len([
            c for c in self._calls.values()
            if c.state == VoLTECallState.ACTIVE
        ])

        return True

    # ---- Incoming SIP handler -----------------------------------------------

    async def _handle_incoming_sip(self, msg: SIPMessage,
                                   addr: tuple) -> None:
        """Handle incoming SIP messages (INVITE, BYE, CANCEL, responses)."""
        if msg.is_response:
            # Delegate response handling to SIP client
            cid = msg.call_id
            if cid in self._sip_client._pending_responses:
                if msg.status_code >= 200:
                    future = self._sip_client._pending_responses.pop(cid)
                    if not future.done():
                        future.set_result(msg)
                elif msg.status_code == 180:
                    # 180 Ringing — update call state to ALERTING
                    call = self._calls.get(cid)
                    if call and call.direction == "MO":
                        call.state = VoLTECallState.RINGING_OUT
                        if self._radio_hal:
                            from hal.radio_hal import CallState
                            await self._radio_hal.update_call_state(
                                call.radio_call_index, CallState.ALERTING
                            )
            return

        # Handle incoming requests
        if msg.method == "INVITE":
            await self._handle_incoming_invite(msg, addr)
        elif msg.method == "BYE":
            await self._handle_incoming_bye(msg, addr)
        elif msg.method == "CANCEL":
            await self._handle_incoming_cancel(msg, addr)

    async def _handle_incoming_bye(self, msg: SIPMessage,
                                   addr: tuple) -> None:
        """Handle incoming BYE (remote party hangs up)."""
        call_id = msg.call_id
        call = self._calls.pop(call_id, None)
        if call:
            await self._stop_media(call)

        # Send 200 OK
        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Via": msg.headers.get("Via", ""),
                "From": msg.headers.get("From", ""),
                "To": msg.headers.get("To", ""),
                "Call-ID": call_id,
                "CSeq": msg.headers.get("CSeq", ""),
            },
        )
        if self._sip_client:
            await self._sip_client.transport.send(ok_response, addr)

        if call and self._radio_hal:
            # Remove call from RadioHAL
            for vc in list(self._radio_hal.voice_calls):
                if vc.sip_call_id == call_id:
                    self._radio_hal.voice_calls.remove(vc)
                    break
            await self._radio_hal._send_indication(1001, {})

        logger.info("VoLTE: remote BYE for call_id=%s", call_id)

        global _volte_state
        _volte_state["active_calls"] = len([
            c for c in self._calls.values()
            if c.state == VoLTECallState.ACTIVE
        ])

    async def _handle_incoming_cancel(self, msg: SIPMessage,
                                      addr: tuple) -> None:
        """Handle incoming CANCEL (remote party cancels before answer)."""
        call_id = msg.call_id
        call = self._calls.pop(call_id, None)
        if call:
            await self._stop_media(call)

        # Send 200 OK for CANCEL
        ok = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Via": msg.headers.get("Via", ""),
                "From": msg.headers.get("From", ""),
                "To": msg.headers.get("To", ""),
                "Call-ID": call_id,
                "CSeq": msg.headers.get("CSeq", ""),
            },
        )
        if self._sip_client:
            await self._sip_client.transport.send(ok, addr)

        if call and self._radio_hal:
            for vc in list(self._radio_hal.voice_calls):
                if vc.sip_call_id == call_id:
                    self._radio_hal.voice_calls.remove(vc)
                    break
            await self._radio_hal._send_indication(1001, {})

        logger.info("VoLTE: remote CANCEL for call_id=%s", call_id)

    # ---- Helpers ------------------------------------------------------------

    async def _send_ack(self, call: VoLTECall, dest: tuple) -> None:
        """Send ACK for a 200 OK response to INVITE."""
        from_uri = self.config.impu
        if not from_uri.startswith("sip:"):
            from_uri = f"sip:{from_uri}"

        ack = SIPMessage(
            method="ACK",
            request_uri=call.remote_uri,
            headers={
                "Via": f"SIP/2.0/{self.config.transport} {self._sip_client.local_ip}:{self._sip_client.local_port};branch={generate_branch()}",
                "Max-Forwards": "70",
                "From": f"<{from_uri}>;tag={generate_tag()}",
                "To": f"<{call.remote_uri}>",
                "Call-ID": call.sip_call_id,
                "CSeq": "1 ACK",
            },
        )
        await self._sip_client.transport.send(ack, dest)

    def _allocate_rtp_port(self) -> int:
        """Allocate the next RTP port (even number per RFC 3550)."""
        port = self._rtp_port_next
        self._rtp_port_next += 2  # RTP uses even, RTCP uses odd
        return port

    async def _start_media(self, call: VoLTECall) -> None:
        """Start the RTP media session for a call."""
        if not call.remote_sdp or not call.rtp_port:
            return

        remote_ip, remote_port = parse_remote_rtp_address(call.remote_sdp)
        if not remote_port:
            logger.warning("VoLTE: no remote RTP port in SDP")
            return

        pt = parse_payload_type(call.remote_sdp, call.codec)
        session = MediaSession()
        try:
            await session.start(
                local_port=call.rtp_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                codec=call.codec,
                payload_type=pt,
            )
            call.media_session = session
            logger.info("VoLTE: media started for call %s", call.sip_call_id)
        except Exception:
            logger.exception("VoLTE: failed to start media for %s",
                             call.sip_call_id)

    async def _stop_media(self, call: VoLTECall) -> None:
        """Stop the RTP media session for a call."""
        if call.media_session:
            await call.media_session.stop()
            call.media_session = None

    def get_calls(self) -> list[dict]:
        """Return list of active calls for management API."""
        return [
            {
                "callId": c.sip_call_id,
                "direction": c.direction,
                "state": c.state.value,
                "number": c.remote_number,
                "codec": c.codec,
                "rtpPort": c.rtp_port,
                "media": c.media_session.get_stats()
                    if c.media_session else None,
            }
            for c in self._calls.values()
        ]


# ---- Legacy VoLTESession (kept for backward compatibility) ------------------


class VoLTESession:
    """
    VoLTE session manager (registration + SDP building).

    Handles VoLTE-specific IMS registration and voice call setup.
    """

    def __init__(
        self,
        credentials: IMSCredentials,
        config: VoLTEConfig,
    ):
        self.creds = credentials
        self.config = config
        self._ims_reg: Optional[IMSRegistration] = None
        self._registered = False

    async def register(self) -> bool:
        """Register for VoLTE services."""
        ims_config = IMSConfig(
            pcscf_address=self.config.pcscf_address,
            pcscf_port=self.config.pcscf_port,
            transport="UDP",
            use_ipsec=self.config.use_ipsec_transport,
        )

        self._ims_reg = IMSRegistration(
            credentials=self.creds,
            config=ims_config,
        )

        success = await self._ims_reg.register()
        self._registered = success
        return success

    async def deregister(self) -> None:
        """Deregister from VoLTE."""
        if self._ims_reg:
            await self._ims_reg.deregister()
            self._registered = False

    def get_status(self) -> dict:
        """Return VoLTE registration status."""
        return {
            "registered": self._registered,
            "state": self._ims_reg.state.value if self._ims_reg else "not_initialized",
            "pcscf": self.config.pcscf_address,
            "codec_priority": self.config.codec_priority,
        }

    def build_sdp_offer(self, local_ip: str, local_port: int = 50000) -> str:
        """Build an SDP offer for a voice call."""
        return build_sdp_offer(local_ip, local_port, self.config.codec_priority)


# ---- SDP utilities ----------------------------------------------------------


def build_sdp_offer(local_ip: str, local_port: int,
                    codec_priority: list[str] = None) -> str:
    """
    Build an SDP offer for a VoLTE voice call.

    Creates SDP with codec preferences:
    - AMR-WB (HD Voice, 16kHz)
    - AMR-NB (8kHz)
    - EVS (Enhanced Voice Services)
    - telephone-event (DTMF)
    """
    if codec_priority is None:
        codec_priority = ["AMR-WB", "AMR-NB", "EVS"]

    codec_map = {
        "AMR-WB": (96, "AMR-WB/16000/1"),
        "AMR-NB": (97, "AMR/8000/1"),
        "EVS": (98, "EVS/16000/1"),
        "telephone-event": (101, "telephone-event/8000"),
    }

    payload_types = []
    rtpmap_lines = []

    for codec in codec_priority:
        if codec in codec_map:
            pt, name = codec_map[codec]
            payload_types.append(str(pt))
            rtpmap_lines.append(f"a=rtpmap:{pt} {name}")

    # Always include telephone-event for DTMF
    pt, name = codec_map["telephone-event"]
    payload_types.append(str(pt))
    rtpmap_lines.append(f"a=rtpmap:{pt} {name}")

    pts = " ".join(payload_types)
    rtpmaps = "\r\n".join(rtpmap_lines)

    return (
        f"v=0\r\n"
        f"o=VirtualPhone 1 1 IN IP4 {local_ip}\r\n"
        f"s=VoLTE Call\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        f"t=0 0\r\n"
        f"m=audio {local_port} RTP/AVP {pts}\r\n"
        f"{rtpmaps}\r\n"
        f"a=ptime:20\r\n"
        f"a=maxptime:240\r\n"
        f"a=sendrecv\r\n"
    )


def _extract_codec_from_sdp(sdp: str) -> str:
    """Extract the first codec name from an SDP answer."""
    match = re.search(r'a=rtpmap:\d+ (\S+)', sdp)
    return match.group(1).split("/")[0] if match else "unknown"


def _extract_number_from_uri(uri: str) -> str:
    """Extract a phone number from a SIP URI."""
    match = re.search(r'sip:([+\d]+)@', uri)
    if match:
        return match.group(1)
    match = re.search(r'tel:([+\d]+)', uri)
    if match:
        return match.group(1)
    return uri
