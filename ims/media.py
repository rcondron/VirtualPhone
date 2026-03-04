"""
VoLTE media session manager.

Manages RTP/RTCP media sessions for active VoLTE voice calls.
Each call gets a MediaSession that handles:
- UDP socket for RTP send/receive
- RTCP sender/receiver reports
- Adaptive jitter buffer for incoming packets
- Codec frame packing/unpacking
- DTMF event generation
- Media statistics tracking

The media session is started when a VoLTE call becomes ACTIVE
(after SIP INVITE 200 OK / ACK) and stopped on call termination.

Architecture:
  VoLTECallManager ──▶ MediaSession.start(local_port, remote_addr, codec)
       │                    │
       │                    ├── RTP send loop (20ms frames)
       │                    ├── RTP receive loop (UDP recv)
       │                    ├── Jitter buffer (reorder, loss concealment)
       │                    └── RTCP reports (every 5 seconds)
       │
       ▼
  MediaSession.stop() ──▶ close UDP socket, flush stats

Reference: RFC 3550 (RTP), RFC 3551 (RTP/AVP), 3GPP TS 26.114
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Awaitable

from ims.rtp import (
    RTPPacket, RTCPSenderReport, RTCPReceiverReport,
    generate_ssrc, ntp_timestamp_now, RTP_VERSION,
    PT_AMR_WB, PT_AMR_NB, PT_EVS, PT_TELEPHONE_EVENT,
)
from ims.codec import (
    AMRFrame, DTMFEvent, get_codec_info,
    AMR_WB_CLOCK_RATE, AMR_NB_CLOCK_RATE,
    AMR_WB_SAMPLES_PER_FRAME, AMR_NB_SAMPLES_PER_FRAME,
    DTMF_EVENTS,
)

logger = logging.getLogger(__name__)


# Module-level media state for management API
_media_state: dict = {
    "active_sessions": 0,
    "total_packets_sent": 0,
    "total_packets_received": 0,
}


def get_media_state() -> dict:
    """Return media pipeline state for the management API."""
    return dict(_media_state)


# ---- Virtual Audio Source ---------------------------------------------------


class AudioSourceType(Enum):
    """Type of virtual audio input for a media session."""
    SILENCE = "silence"     # SID comfort noise frames
    TONE = "tone"           # Synthetic sine wave tone (for testing)
    ZERO = "zero"           # Zero-filled AMR frames (current default)
    LOOPBACK = "loopback"   # Echo received audio back to sender


class VirtualAudioSource:
    """
    Virtual audio source for MediaSession.

    Provides configurable audio input since the virtual phone has no
    real microphone. Each source type generates AMR frames differently:

    - SILENCE: SID (Silence Insertion Descriptor) comfort noise frames
    - TONE: Synthetic tone encoded as AMR frame data (for call testing)
    - ZERO: Zero-filled AMR frames (default, existing behavior)
    - LOOPBACK: Echoes received RTP payload back to sender

    Usage:
        source = VirtualAudioSource(AudioSourceType.TONE, frequency=440)
        session.set_audio_source(source)
    """

    def __init__(self, source_type: AudioSourceType = AudioSourceType.SILENCE,
                 frequency: int = 440):
        self.source_type = source_type
        self.frequency = frequency  # Hz, used for TONE mode
        self._frame_count = 0
        self._loopback_buffer: deque[bytes] = deque(maxlen=50)

    def generate_frame(self, is_wideband: bool = True,
                       mode: int = 8) -> AMRFrame:
        """
        Generate the next AMR frame based on the audio source type.

        Args:
            is_wideband: True for AMR-WB, False for AMR-NB
            mode: AMR codec mode (0-8 for WB, 0-7 for NB)

        Returns:
            An AMRFrame ready for RTP packetization.
        """
        self._frame_count += 1

        if self.source_type == AudioSourceType.SILENCE:
            return AMRFrame.silence(is_wideband=is_wideband)

        if self.source_type == AudioSourceType.LOOPBACK:
            if self._loopback_buffer:
                data = self._loopback_buffer.popleft()
                return AMRFrame(
                    mode=mode, quality=True,
                    data=data, is_wideband=is_wideband,
                )
            # No buffered data — send silence
            return AMRFrame.silence(is_wideband=is_wideband)

        if self.source_type == AudioSourceType.TONE:
            # Generate a synthetic tone pattern as AMR frame data.
            # Real tone encoding would require an AMR encoder; we
            # approximate by writing a sine pattern into the frame
            # bytes. This won't decode to a real tone but produces
            # non-zero, varying frame data useful for testing.
            frame_size = AMRFrame(mode=mode, is_wideband=is_wideband).frame_size
            sample_rate = 16000 if is_wideband else 8000
            samples_per_frame = 320 if is_wideband else 160
            data = bytearray(frame_size)
            for j in range(min(frame_size, samples_per_frame)):
                t = (self._frame_count * samples_per_frame + j) / sample_rate
                val = int(127 * math.sin(2 * math.pi * self.frequency * t))
                data[j] = (val + 128) & 0xFF
            return AMRFrame(
                mode=mode, quality=True,
                data=bytes(data), is_wideband=is_wideband,
            )

        # ZERO (default) — zero-filled frame
        frame_size = AMRFrame(mode=mode, is_wideband=is_wideband).frame_size
        return AMRFrame(
            mode=mode, quality=True,
            data=b"\x00" * frame_size, is_wideband=is_wideband,
        )

    def feed_loopback(self, payload: bytes) -> None:
        """Feed received RTP payload into the loopback buffer."""
        if self.source_type == AudioSourceType.LOOPBACK:
            self._loopback_buffer.append(payload)

    @property
    def frame_count(self) -> int:
        """Number of frames generated so far."""
        return self._frame_count


# ---- Jitter Buffer ----------------------------------------------------------


@dataclass
class JitterBufferEntry:
    """A single entry in the jitter buffer."""
    sequence_number: int
    timestamp: int
    payload: bytes
    arrival_time: float


class JitterBuffer:
    """
    Adaptive jitter buffer for RTP packet reordering.

    Buffers incoming RTP packets and releases them in sequence order
    with a configurable playout delay. Handles:
    - Out-of-order packet reordering
    - Duplicate detection
    - Late packet discarding
    - Adaptive delay based on observed jitter

    The buffer depth adapts between min_depth and max_depth based
    on the inter-arrival jitter measured from incoming packets.
    """

    def __init__(self, min_depth: int = 2, max_depth: int = 10,
                 target_depth: int = 4):
        self.min_depth = min_depth
        self.max_depth = max_depth
        self.target_depth = target_depth
        self._buffer: deque[JitterBufferEntry] = deque(maxlen=max_depth * 2)
        self._next_seq: Optional[int] = None
        self._last_arrival: float = 0.0
        self._jitter: float = 0.0
        # Stats
        self.packets_received: int = 0
        self.packets_played: int = 0
        self.packets_lost: int = 0
        self.packets_late: int = 0
        self.packets_duplicate: int = 0

    def put(self, packet: RTPPacket) -> None:
        """Add an incoming RTP packet to the buffer."""
        now = time.monotonic()
        seq = packet.sequence_number

        self.packets_received += 1

        # Initialize sequence tracking
        if self._next_seq is None:
            self._next_seq = seq

        # Duplicate detection
        for entry in self._buffer:
            if entry.sequence_number == seq:
                self.packets_duplicate += 1
                return

        # Update jitter estimate (RFC 3550 Section 6.4.1)
        if self._last_arrival > 0:
            transit_diff = abs(now - self._last_arrival - 0.020)  # 20ms expected
            self._jitter += (transit_diff - self._jitter) / 16.0
        self._last_arrival = now

        entry = JitterBufferEntry(
            sequence_number=seq,
            timestamp=packet.timestamp,
            payload=packet.payload,
            arrival_time=now,
        )

        # Insert sorted by sequence number
        inserted = False
        for i in range(len(self._buffer)):
            if self._buffer[i].sequence_number > seq:
                self._buffer.insert(i, entry)
                inserted = True
                break
        if not inserted:
            self._buffer.append(entry)

    def get(self) -> Optional[bytes]:
        """
        Get the next packet payload in sequence order.

        Returns None if the buffer doesn't have enough depth yet
        or the next packet hasn't arrived.
        """
        if len(self._buffer) < self.target_depth:
            return None

        if not self._buffer:
            return None

        # Check if the front of the buffer is the expected sequence
        front = self._buffer[0]
        if self._next_seq is not None:
            # Handle sequence number wrap-around
            diff = (front.sequence_number - self._next_seq) & 0xFFFF
            if diff > 0x8000:
                # This is an old packet (behind our window), discard
                self._buffer.popleft()
                self.packets_late += 1
                return self.get()  # Try next
            elif diff > 0:
                # Gap — the expected packet is missing
                self.packets_lost += 1
                self._next_seq = (self._next_seq + 1) & 0xFFFF
                return b""  # Signal loss for concealment

        entry = self._buffer.popleft()
        self._next_seq = (entry.sequence_number + 1) & 0xFFFF
        self.packets_played += 1
        return entry.payload

    @property
    def depth(self) -> int:
        """Current buffer depth (number of packets)."""
        return len(self._buffer)

    @property
    def jitter_ms(self) -> float:
        """Estimated interarrival jitter in milliseconds."""
        return self._jitter * 1000

    def reset(self) -> None:
        """Clear the buffer."""
        self._buffer.clear()
        self._next_seq = None
        self._last_arrival = 0.0
        self._jitter = 0.0

    def get_stats(self) -> dict:
        """Return buffer statistics."""
        return {
            "depth": self.depth,
            "jitter_ms": round(self.jitter_ms, 2),
            "received": self.packets_received,
            "played": self.packets_played,
            "lost": self.packets_lost,
            "late": self.packets_late,
            "duplicate": self.packets_duplicate,
        }


# ---- Media Session ----------------------------------------------------------


@dataclass
class MediaStats:
    """Media session statistics."""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    rtcp_sr_sent: int = 0
    rtcp_rr_sent: int = 0
    start_time: float = 0.0
    codec: str = ""


class MediaSession:
    """
    RTP media session for a single VoLTE call.

    Manages bidirectional RTP media flow between local and remote
    endpoints. Handles packet send/receive, jitter buffering,
    codec framing, RTCP reports, and DTMF events.
    """

    def __init__(self, ssrc: int = 0):
        self.ssrc = ssrc or generate_ssrc()
        self.local_port: int = 0
        self.remote_addr: tuple[str, int] = ("", 0)
        self.codec: str = "AMR-WB"
        self.payload_type: int = PT_AMR_WB

        # RTP state
        self._seq: int = 0
        self._timestamp: int = 0
        self._clock_rate: int = AMR_WB_CLOCK_RATE
        self._samples_per_frame: int = AMR_WB_SAMPLES_PER_FRAME

        # Transport
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._rtcp_transport: Optional[asyncio.DatagramTransport] = None

        # Jitter buffer
        self.jitter_buffer = JitterBuffer()

        # Stats
        self.stats = MediaStats()

        # Tasks
        self._rtcp_task: Optional[asyncio.Task] = None
        self._active = False

        # Hold state
        self._held = False
        self._direction: str = "sendrecv"  # sendrecv, sendonly, recvonly, inactive

        # Virtual audio source
        self._audio_source = VirtualAudioSource(AudioSourceType.SILENCE)

        # Callbacks
        self._on_dtmf: Optional[Callable[[str], Awaitable[None]]] = None

    async def start(self, local_port: int, remote_ip: str,
                    remote_port: int, codec: str = "AMR-WB",
                    payload_type: int = PT_AMR_WB) -> None:
        """
        Start the media session.

        Opens UDP sockets for RTP (even port) and RTCP (odd port),
        configures codec parameters, and starts the RTCP report timer.
        """
        global _media_state

        self.local_port = local_port
        self.remote_addr = (remote_ip, remote_port)
        self.codec = codec
        self.payload_type = payload_type

        # Configure codec parameters
        info = get_codec_info(codec)
        self._clock_rate = info["clock_rate"]
        self._samples_per_frame = info["samples_per_frame"]

        # Map codec name to payload type
        codec_pt_map = {
            "AMR-WB": PT_AMR_WB,
            "AMR": PT_AMR_NB,
            "EVS": PT_EVS,
        }
        if payload_type == PT_AMR_WB:
            self.payload_type = codec_pt_map.get(codec, PT_AMR_WB)

        # Open RTP UDP socket
        loop = asyncio.get_event_loop()

        class RTPProtocol(asyncio.DatagramProtocol):
            def __init__(self, session):
                self.session = session

            def datagram_received(self, data, addr):
                self.session._on_rtp_received(data, addr)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: RTPProtocol(self),
                local_addr=("0.0.0.0", local_port),
            )
            self._transport = transport
        except OSError as e:
            logger.warning("Media: could not bind RTP port %d: %s",
                          local_port, e)
            # Continue without transport for testing
            self._transport = None

        # Open RTCP UDP socket (port + 1)
        try:
            rtcp_transport, _ = await loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                local_addr=("0.0.0.0", local_port + 1),
            )
            self._rtcp_transport = rtcp_transport
        except OSError:
            self._rtcp_transport = None

        self._active = True
        self.stats.start_time = time.monotonic()
        self.stats.codec = codec

        # Start RTCP report timer
        self._rtcp_task = asyncio.create_task(self._rtcp_loop())

        _media_state["active_sessions"] += 1
        logger.info("Media session started: port=%d → %s:%d codec=%s ssrc=%08x",
                     local_port, remote_ip, remote_port, codec, self.ssrc)

    async def stop(self) -> None:
        """Stop the media session and release resources."""
        global _media_state

        self._active = False

        if self._rtcp_task:
            self._rtcp_task.cancel()
            try:
                await self._rtcp_task
            except asyncio.CancelledError:
                pass

        if self._transport:
            self._transport.close()
        if self._rtcp_transport:
            self._rtcp_transport.close()

        _media_state["active_sessions"] = max(0,
            _media_state["active_sessions"] - 1)
        _media_state["total_packets_sent"] += self.stats.packets_sent
        _media_state["total_packets_received"] += self.stats.packets_received

        logger.info("Media session stopped: sent=%d recv=%d codec=%s",
                     self.stats.packets_sent, self.stats.packets_received,
                     self.stats.codec)

    def send_frame(self, frame_data: bytes, marker: bool = False) -> None:
        """
        Send a codec frame as an RTP packet.

        Args:
            frame_data: Codec frame bytes (e.g., AMR-WB octet-aligned payload)
            marker: Marker bit (True for first frame after silence)
        """
        if not self._active or self._held:
            return

        packet = RTPPacket(
            marker=marker,
            payload_type=self.payload_type,
            sequence_number=self._seq & 0xFFFF,
            timestamp=self._timestamp & 0xFFFFFFFF,
            ssrc=self.ssrc,
            payload=frame_data,
        )

        self._seq += 1
        self._timestamp += self._samples_per_frame

        raw = packet.to_bytes()
        if self._transport:
            self._transport.sendto(raw, self.remote_addr)

        self.stats.packets_sent += 1
        self.stats.bytes_sent += len(raw)

    def set_audio_source(self, source: VirtualAudioSource) -> None:
        """
        Configure the virtual audio source for this session.

        Args:
            source: VirtualAudioSource with desired source type.
        """
        self._audio_source = source
        logger.info("Media session audio source set to %s (ssrc=%08x)",
                     source.source_type.value, self.ssrc)

    def send_amr_frame(self, mode: int = 8,
                       silence: bool = False) -> None:
        """
        Send an AMR-WB/NB frame.

        If silence=True, sends a SID (comfort noise) frame.
        Otherwise, uses the configured virtual audio source to generate
        the frame data. The audio source defaults to SILENCE (SID frames).
        """
        is_wb = self.codec.upper() in ("AMR-WB", "AMRWB")
        if silence:
            frame = AMRFrame.silence(is_wideband=is_wb)
        else:
            frame = self._audio_source.generate_frame(is_wideband=is_wb, mode=mode)
        self.send_frame(frame.to_rtp_payload(), marker=(self._seq == 0))

    def send_dtmf(self, digit: str, duration_ms: int = 160) -> None:
        """
        Send a DTMF event as an RFC 4733 telephone-event.

        Sends three packets: start, ongoing, and end.
        """
        if digit not in DTMF_EVENTS:
            return

        duration_samples = int(duration_ms * self._clock_rate / 1000)

        # Start event
        event = DTMFEvent.from_digit(digit, duration=duration_samples // 3,
                                     end=False)
        self._send_dtmf_packet(event, marker=True)

        # Ongoing event
        event.duration = duration_samples * 2 // 3
        self._send_dtmf_packet(event, marker=False)

        # End event (sent 3 times per RFC 4733)
        event.end = True
        event.duration = duration_samples
        for _ in range(3):
            self._send_dtmf_packet(event, marker=False)

    def _send_dtmf_packet(self, event: DTMFEvent,
                          marker: bool = False) -> None:
        """Send a single DTMF event RTP packet."""
        packet = RTPPacket(
            marker=marker,
            payload_type=PT_TELEPHONE_EVENT,
            sequence_number=self._seq & 0xFFFF,
            timestamp=self._timestamp & 0xFFFFFFFF,
            ssrc=self.ssrc,
            payload=event.to_rtp_payload(),
        )
        self._seq += 1

        raw = packet.to_bytes()
        if self._transport:
            self._transport.sendto(raw, self.remote_addr)

        self.stats.packets_sent += 1
        self.stats.bytes_sent += len(raw)

    def _on_rtp_received(self, data: bytes, addr: tuple) -> None:
        """Handle an incoming RTP packet."""
        try:
            packet = RTPPacket.from_bytes(data)
        except ValueError as e:
            logger.debug("Media: invalid RTP packet: %s", e)
            return

        self.stats.packets_received += 1
        self.stats.bytes_received += len(data)

        # Check for DTMF event
        if packet.payload_type == PT_TELEPHONE_EVENT:
            try:
                event = DTMFEvent.from_rtp_payload(packet.payload)
                if event.end and self._on_dtmf:
                    asyncio.ensure_future(self._on_dtmf(event.digit))
            except ValueError:
                pass
            return

        # Feed payload to loopback audio source if configured
        self._audio_source.feed_loopback(packet.payload)

        # Add to jitter buffer
        self.jitter_buffer.put(packet)

    async def _rtcp_loop(self) -> None:
        """Send RTCP reports periodically (every 5 seconds per RFC 3550)."""
        try:
            while self._active:
                await asyncio.sleep(5)
                if not self._active:
                    break
                self._send_rtcp_sr()
                self._send_rtcp_rr()
        except asyncio.CancelledError:
            pass

    def _send_rtcp_sr(self) -> None:
        """Send an RTCP Sender Report."""
        ntp_msw, ntp_lsw = ntp_timestamp_now()
        sr = RTCPSenderReport(
            ssrc=self.ssrc,
            ntp_timestamp_msw=ntp_msw,
            ntp_timestamp_lsw=ntp_lsw,
            rtp_timestamp=self._timestamp & 0xFFFFFFFF,
            sender_packet_count=self.stats.packets_sent,
            sender_octet_count=self.stats.bytes_sent,
        )

        if self._rtcp_transport:
            rtcp_addr = (self.remote_addr[0], self.remote_addr[1] + 1)
            self._rtcp_transport.sendto(sr.to_bytes(), rtcp_addr)

        self.stats.rtcp_sr_sent += 1

    def _send_rtcp_rr(self) -> None:
        """Send an RTCP Receiver Report."""
        buf_stats = self.jitter_buffer.get_stats()
        total_expected = buf_stats["received"] + buf_stats["lost"]
        fraction = 0
        if total_expected > 0:
            fraction = int(256 * buf_stats["lost"] / total_expected)

        rr = RTCPReceiverReport(
            ssrc=self.ssrc,
            source_ssrc=0,  # Will be set from received packets
            fraction_lost=min(255, fraction),
            cumulative_lost=buf_stats["lost"],
            highest_seq=buf_stats["received"],
            jitter=int(buf_stats["jitter_ms"] * self._clock_rate / 1000),
        )

        if self._rtcp_transport:
            rtcp_addr = (self.remote_addr[0], self.remote_addr[1] + 1)
            self._rtcp_transport.sendto(rr.to_bytes(), rtcp_addr)

        self.stats.rtcp_rr_sent += 1

    def hold(self) -> None:
        """
        Put the media session on hold.

        Stops sending RTP but keeps receiving (sendonly from remote).
        The SDP direction should be changed to 'sendonly' or 'inactive'
        via SIP re-INVITE — this method handles the media side.
        """
        if not self._active:
            return
        self._held = True
        self._direction = "sendonly"
        logger.info("Media session held (ssrc=%08x)", self.ssrc)

    def resume(self) -> None:
        """
        Resume the media session from hold.

        Restores bidirectional media flow (sendrecv).
        """
        if not self._active:
            return
        self._held = False
        self._direction = "sendrecv"
        logger.info("Media session resumed (ssrc=%08x)", self.ssrc)

    @property
    def is_held(self) -> bool:
        """Whether the session is currently on hold."""
        return self._held

    @property
    def direction(self) -> str:
        """Current media direction (sendrecv, sendonly, recvonly, inactive)."""
        return self._direction

    def set_dtmf_callback(self, cb: Callable[[str], Awaitable[None]]) -> None:
        """Set callback for received DTMF digits."""
        self._on_dtmf = cb

    def get_stats(self) -> dict:
        """Return session statistics."""
        elapsed = time.monotonic() - self.stats.start_time \
            if self.stats.start_time > 0 else 0
        return {
            "ssrc": f"{self.ssrc:08x}",
            "codec": self.stats.codec,
            "audio_source": self._audio_source.source_type.value,
            "held": self._held,
            "direction": self._direction,
            "packets_sent": self.stats.packets_sent,
            "packets_received": self.stats.packets_received,
            "bytes_sent": self.stats.bytes_sent,
            "bytes_received": self.stats.bytes_received,
            "rtcp_sr_sent": self.stats.rtcp_sr_sent,
            "rtcp_rr_sent": self.stats.rtcp_rr_sent,
            "duration_seconds": round(elapsed, 1),
            "jitter_buffer": self.jitter_buffer.get_stats(),
        }


# ---- SDP Parsing Helpers -----------------------------------------------------


def parse_remote_rtp_address(sdp: str) -> tuple[str, int]:
    """
    Extract the remote RTP IP and port from an SDP answer.

    Looks for:
      c=IN IP4 <ip>
      m=audio <port> RTP/AVP ...
    """
    ip = "0.0.0.0"
    port = 0

    match = re.search(r'c=IN IP[46] (\S+)', sdp)
    if match:
        ip = match.group(1)

    match = re.search(r'm=audio (\d+)', sdp)
    if match:
        port = int(match.group(1))

    return ip, port


def parse_payload_type(sdp: str, codec: str) -> int:
    """Extract the payload type number for a codec from SDP."""
    codec_clean = codec.upper().replace("-", "").replace("_", "")
    match = re.search(r'a=rtpmap:(\d+) ' + re.escape(codec), sdp, re.IGNORECASE)
    if match:
        return int(match.group(1))
    # Fallback defaults
    defaults = {"AMRWB": PT_AMR_WB, "AMR": PT_AMR_NB, "EVS": PT_EVS}
    return defaults.get(codec_clean, PT_AMR_WB)
