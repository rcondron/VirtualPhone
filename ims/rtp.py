"""
RTP (Real-time Transport Protocol) packet engine.

Handles RTP packet construction, parsing, and sequencing per RFC 3550.
This is the wire format layer that carries voice media for VoLTE calls.

RTP Header (12 bytes fixed + CSRCs):
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           synchronization source (SSRC) identifier            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Reference: RFC 3550, RFC 3551 (RTP/AVP profile)
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional


# RTP version
RTP_VERSION = 2

# Common payload types for VoLTE (from SDP negotiation)
PT_AMR_WB = 96       # Dynamic (assigned in SDP)
PT_AMR_NB = 97
PT_EVS = 98
PT_TELEPHONE_EVENT = 101


@dataclass
class RTPPacket:
    """
    An RTP packet (RFC 3550).

    Attributes:
        version: RTP version (always 2)
        padding: Padding flag
        extension: Header extension flag
        csrc_count: Contributing source count
        marker: Marker bit (e.g., first packet of a talkspurt)
        payload_type: Payload type number
        sequence_number: Packet sequence number (wraps at 65535)
        timestamp: Media timestamp (sample clock)
        ssrc: Synchronization source identifier
        csrc_list: Contributing source identifiers
        payload: Media data bytes
    """
    version: int = RTP_VERSION
    padding: bool = False
    extension: bool = False
    csrc_count: int = 0
    marker: bool = False
    payload_type: int = PT_AMR_WB
    sequence_number: int = 0
    timestamp: int = 0
    ssrc: int = 0
    csrc_list: list[int] = field(default_factory=list)
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        # First byte: V(2)|P(1)|X(1)|CC(4)
        byte0 = (self.version << 6) | (int(self.padding) << 5) | \
                (int(self.extension) << 4) | (self.csrc_count & 0x0F)
        # Second byte: M(1)|PT(7)
        byte1 = (int(self.marker) << 7) | (self.payload_type & 0x7F)

        header = struct.pack("!BBHII",
                             byte0, byte1,
                             self.sequence_number & 0xFFFF,
                             self.timestamp & 0xFFFFFFFF,
                             self.ssrc & 0xFFFFFFFF)

        # Append CSRC list
        for csrc in self.csrc_list[:self.csrc_count]:
            header += struct.pack("!I", csrc & 0xFFFFFFFF)

        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> RTPPacket:
        """Parse an RTP packet from wire bytes."""
        if len(data) < 12:
            raise ValueError(f"RTP packet too short: {len(data)} bytes (min 12)")

        byte0, byte1, seq, ts, ssrc = struct.unpack("!BBHII", data[:12])

        version = (byte0 >> 6) & 0x03
        if version != RTP_VERSION:
            raise ValueError(f"Invalid RTP version: {version}")

        padding = bool(byte0 & 0x20)
        extension = bool(byte0 & 0x10)
        cc = byte0 & 0x0F
        marker = bool(byte1 & 0x80)
        pt = byte1 & 0x7F

        offset = 12
        csrc_list = []
        for _ in range(cc):
            if offset + 4 > len(data):
                break
            csrc_list.append(struct.unpack("!I", data[offset:offset + 4])[0])
            offset += 4

        # Skip header extension if present
        if extension and offset + 4 <= len(data):
            _, ext_len = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4 + ext_len * 4

        # Handle padding
        payload_end = len(data)
        if padding and len(data) > offset:
            pad_len = data[-1]
            payload_end -= pad_len

        payload = data[offset:payload_end]

        return cls(
            version=version,
            padding=padding,
            extension=extension,
            csrc_count=cc,
            marker=marker,
            payload_type=pt,
            sequence_number=seq,
            timestamp=ts,
            ssrc=ssrc,
            csrc_list=csrc_list,
            payload=payload,
        )

    @property
    def header_size(self) -> int:
        """Size of the RTP header in bytes."""
        return 12 + 4 * self.csrc_count


@dataclass
class RTCPSenderReport:
    """
    RTCP Sender Report (SR) packet — RFC 3550 Section 6.4.1.

    Sent by the media sender to report transmission statistics.
    """
    ssrc: int = 0
    ntp_timestamp_msw: int = 0    # NTP timestamp (most significant word)
    ntp_timestamp_lsw: int = 0    # NTP timestamp (least significant word)
    rtp_timestamp: int = 0
    sender_packet_count: int = 0
    sender_octet_count: int = 0

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        # RTCP header: V=2, P=0, RC=0, PT=200 (SR), length
        payload = struct.pack("!IIIII",
                              self.ntp_timestamp_msw,
                              self.ntp_timestamp_lsw,
                              self.rtp_timestamp,
                              self.sender_packet_count,
                              self.sender_octet_count)
        # Length in 32-bit words minus one
        length = (4 + len(payload)) // 4 - 1
        header = struct.pack("!BBHI",
                             0x80,       # V=2, P=0, RC=0
                             200,        # PT = SR
                             length,
                             self.ssrc)
        return header + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> RTCPSenderReport:
        """Parse from wire bytes."""
        if len(data) < 28:
            raise ValueError(f"RTCP SR too short: {len(data)} bytes")
        _, _, _, ssrc = struct.unpack("!BBHI", data[:8])
        ntp_msw, ntp_lsw, rtp_ts, pkt_count, oct_count = struct.unpack(
            "!IIIII", data[8:28])
        return cls(
            ssrc=ssrc,
            ntp_timestamp_msw=ntp_msw,
            ntp_timestamp_lsw=ntp_lsw,
            rtp_timestamp=rtp_ts,
            sender_packet_count=pkt_count,
            sender_octet_count=oct_count,
        )


@dataclass
class RTCPReceiverReport:
    """
    RTCP Receiver Report (RR) packet — RFC 3550 Section 6.4.2.

    Sent by receivers to report reception quality.
    """
    ssrc: int = 0
    # Report block for a single source
    source_ssrc: int = 0
    fraction_lost: int = 0       # 8-bit fraction
    cumulative_lost: int = 0     # 24-bit total lost
    highest_seq: int = 0         # Extended highest sequence number received
    jitter: int = 0              # Interarrival jitter
    last_sr: int = 0             # Last SR timestamp (middle 32 bits of NTP)
    delay_since_sr: int = 0      # Delay since last SR (1/65536 seconds)

    def to_bytes(self) -> bytes:
        """Serialize to wire format."""
        report_block = struct.pack("!I", self.source_ssrc)
        # fraction_lost (8 bits) + cumulative_lost (24 bits)
        lost_word = ((self.fraction_lost & 0xFF) << 24) | \
                    (self.cumulative_lost & 0x00FFFFFF)
        report_block += struct.pack("!IIIII",
                                    lost_word,
                                    self.highest_seq,
                                    self.jitter,
                                    self.last_sr,
                                    self.delay_since_sr)
        # RC=1 (one report block)
        length = (4 + len(report_block)) // 4 - 1
        header = struct.pack("!BBHI",
                             0x81,       # V=2, P=0, RC=1
                             201,        # PT = RR
                             length,
                             self.ssrc)
        return header + report_block

    @classmethod
    def from_bytes(cls, data: bytes) -> RTCPReceiverReport:
        """Parse from wire bytes."""
        if len(data) < 32:
            raise ValueError(f"RTCP RR too short: {len(data)} bytes")
        _, _, _, ssrc = struct.unpack("!BBHI", data[:8])
        source_ssrc = struct.unpack("!I", data[8:12])[0]
        lost_word, highest_seq, jitter, last_sr, delay = struct.unpack(
            "!IIIII", data[12:32])
        fraction_lost = (lost_word >> 24) & 0xFF
        cumulative_lost = lost_word & 0x00FFFFFF
        return cls(
            ssrc=ssrc,
            source_ssrc=source_ssrc,
            fraction_lost=fraction_lost,
            cumulative_lost=cumulative_lost,
            highest_seq=highest_seq,
            jitter=jitter,
            last_sr=last_sr,
            delay_since_sr=delay,
        )


def generate_ssrc() -> int:
    """Generate a random SSRC identifier."""
    return int.from_bytes(os.urandom(4), "big")


def ntp_timestamp_now() -> tuple[int, int]:
    """Return (MSW, LSW) of the current NTP timestamp."""
    # NTP epoch is 1900-01-01; Unix epoch is 1970-01-01
    NTP_EPOCH_OFFSET = 2208988800
    now = time.time()
    ntp_seconds = int(now) + NTP_EPOCH_OFFSET
    ntp_fraction = int((now % 1) * (2 ** 32))
    return ntp_seconds, ntp_fraction
