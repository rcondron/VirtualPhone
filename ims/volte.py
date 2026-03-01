"""
VoLTE (Voice over LTE) support.

VoLTE uses IMS over the LTE bearer with IPsec transport mode
for SIP signaling protection. The media (RTP) flows directly
over the LTE bearer.

Key differences from VoWiFi:
- No ePDG tunnel needed (direct LTE bearer)
- IPsec transport mode (not tunnel mode)
- P-CSCF discovered via PCO in PDN connection
- Dedicated EPS bearers for voice (QCI=1)

Reference: 3GPP TS 24.229, 3GPP TS 23.228
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from ims.registration import IMSRegistration, IMSCredentials, IMSConfig, IMSRegState

logger = logging.getLogger(__name__)


@dataclass
class VoLTEConfig:
    """VoLTE-specific configuration."""
    pcscf_address: str = ""
    pcscf_port: int = 5060
    use_ipsec_transport: bool = True  # IPsec transport mode for SIP
    # QoS parameters
    qci: int = 1                # QoS Class Identifier (1 = conversational voice)
    gbr_ul: int = 41000         # Guaranteed bit rate uplink (bps)
    gbr_dl: int = 41000         # Guaranteed bit rate downlink (bps)
    # Codec preferences
    codec_priority: list[str] = None

    def __post_init__(self):
        if self.codec_priority is None:
            self.codec_priority = ["AMR-WB", "AMR-NB", "EVS"]


class VoLTESession:
    """
    VoLTE session manager.

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
        """
        Build an SDP offer for a voice call.

        Creates SDP with codec preferences for VoLTE.
        AMR-WB (HD Voice) is preferred over AMR-NB.
        """
        codecs = []
        payload_types = []
        rtpmap_lines = []

        codec_map = {
            "AMR-WB": (96, "AMR-WB/16000/1"),
            "AMR-NB": (97, "AMR/8000/1"),
            "EVS": (98, "EVS/16000/1"),
            "telephone-event": (101, "telephone-event/8000"),
        }

        for codec in self.config.codec_priority:
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
