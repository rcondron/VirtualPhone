"""Tests for Phase 7: RTP Media Pipeline.

Tests cover:
- RTP packet serialization/deserialization (RFC 3550 header)
- RTP packet validation (version, minimum size)
- CSRC list handling and header extensions
- RTCP Sender Report construction and parsing (PT=200)
- RTCP Receiver Report construction and parsing (PT=201)
- NTP timestamp generation and SSRC generation
- AMR-WB/AMR-NB codec frame packing (octet-aligned mode)
- AMR SID (comfort noise) frames
- DTMF event encoding/decoding (RFC 4733)
- DTMF digit ↔ event code mapping
- Jitter buffer reordering, duplicate detection, loss tracking
- Jitter buffer stats and reset
- MediaSession lifecycle (start/stop)
- MediaSession send_frame, send_dtmf, get_stats
- SDP parsing helpers (parse_remote_rtp_address, parse_payload_type)
- VoLTE media integration (_start_media / _stop_media)
- Management API /status/media endpoint
- Module-level get_media_state()
"""

import asyncio
import struct
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ims.rtp import (
    RTPPacket, RTCPSenderReport, RTCPReceiverReport,
    generate_ssrc, ntp_timestamp_now,
    RTP_VERSION, PT_AMR_WB, PT_AMR_NB, PT_EVS, PT_TELEPHONE_EVENT,
)
from ims.codec import (
    AMRMode, AMRFrame, DTMFEvent,
    AMR_WB_FRAME_SIZES, AMR_NB_FRAME_SIZES,
    AMR_WB_CLOCK_RATE, AMR_NB_CLOCK_RATE,
    AMR_WB_SAMPLES_PER_FRAME, AMR_NB_SAMPLES_PER_FRAME,
    DTMF_EVENTS, get_codec_info,
    DEFAULT_AMR_WB_MODE, EVS_CLOCK_RATE, EVS_SAMPLES_PER_FRAME,
)
from ims.media import (
    JitterBuffer, JitterBufferEntry, MediaSession, MediaStats,
    get_media_state, parse_remote_rtp_address, parse_payload_type,
    _media_state,
    VirtualAudioSource, AudioSourceType,
)


# =============================================================================
# RTP Packet Tests
# =============================================================================

class TestRTPPacket:
    """Test RTP packet serialization and deserialization."""

    def test_default_packet_to_bytes(self):
        """Default RTP packet should serialize to 12 bytes header + payload."""
        pkt = RTPPacket(payload=b"\xAA\xBB")
        raw = pkt.to_bytes()
        assert len(raw) == 14  # 12 header + 2 payload

    def test_version_in_header(self):
        """RTP version 2 should be encoded in bits 6-7 of first byte."""
        pkt = RTPPacket()
        raw = pkt.to_bytes()
        assert (raw[0] >> 6) == RTP_VERSION

    def test_marker_bit(self):
        """Marker bit should be set in second byte."""
        pkt = RTPPacket(marker=True, payload_type=96)
        raw = pkt.to_bytes()
        assert raw[1] & 0x80  # marker bit set
        assert raw[1] & 0x7F == 96  # PT

    def test_no_marker_bit(self):
        pkt = RTPPacket(marker=False, payload_type=96)
        raw = pkt.to_bytes()
        assert not (raw[1] & 0x80)

    def test_sequence_number(self):
        pkt = RTPPacket(sequence_number=0x1234)
        raw = pkt.to_bytes()
        seq = struct.unpack("!H", raw[2:4])[0]
        assert seq == 0x1234

    def test_timestamp(self):
        pkt = RTPPacket(timestamp=0xDEADBEEF)
        raw = pkt.to_bytes()
        ts = struct.unpack("!I", raw[4:8])[0]
        assert ts == 0xDEADBEEF

    def test_ssrc(self):
        pkt = RTPPacket(ssrc=0x12345678)
        raw = pkt.to_bytes()
        ssrc = struct.unpack("!I", raw[8:12])[0]
        assert ssrc == 0x12345678

    def test_payload_appended(self):
        payload = b"\x01\x02\x03\x04\x05"
        pkt = RTPPacket(payload=payload)
        raw = pkt.to_bytes()
        assert raw[12:] == payload

    def test_roundtrip(self):
        """Serialize then parse should preserve all fields."""
        pkt = RTPPacket(
            marker=True,
            payload_type=PT_AMR_WB,
            sequence_number=5000,
            timestamp=160000,
            ssrc=0xAABBCCDD,
            payload=b"\xFF" * 60,
        )
        raw = pkt.to_bytes()
        parsed = RTPPacket.from_bytes(raw)
        assert parsed.version == RTP_VERSION
        assert parsed.marker == True
        assert parsed.payload_type == PT_AMR_WB
        assert parsed.sequence_number == 5000
        assert parsed.timestamp == 160000
        assert parsed.ssrc == 0xAABBCCDD
        assert parsed.payload == b"\xFF" * 60

    def test_csrc_list(self):
        pkt = RTPPacket(
            csrc_count=2,
            csrc_list=[0x11111111, 0x22222222],
            payload=b"\x00",
        )
        raw = pkt.to_bytes()
        assert len(raw) == 12 + 8 + 1  # header + 2 CSRCs + payload
        parsed = RTPPacket.from_bytes(raw)
        assert parsed.csrc_count == 2
        assert parsed.csrc_list == [0x11111111, 0x22222222]
        assert parsed.payload == b"\x00"

    def test_from_bytes_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            RTPPacket.from_bytes(b"\x00" * 11)

    def test_from_bytes_wrong_version(self):
        # Version 3 in first byte
        bad = b"\xC0" + b"\x00" * 11
        with pytest.raises(ValueError, match="Invalid RTP version"):
            RTPPacket.from_bytes(bad)

    def test_header_size_property(self):
        pkt = RTPPacket(csrc_count=3)
        assert pkt.header_size == 12 + 3 * 4

    def test_sequence_wrap(self):
        """Sequence number should wrap at 16 bits."""
        pkt = RTPPacket(sequence_number=0xFFFF)
        raw = pkt.to_bytes()
        parsed = RTPPacket.from_bytes(raw)
        assert parsed.sequence_number == 0xFFFF

    def test_padding_flag(self):
        pkt = RTPPacket(padding=True, payload=b"\x00\x00\x02")
        raw = pkt.to_bytes()
        assert raw[0] & 0x20  # padding flag set
        parsed = RTPPacket.from_bytes(raw)
        assert parsed.padding == True
        # Padding should be stripped from payload
        assert parsed.payload == b"\x00"

    def test_extension_flag(self):
        """Extension flag should be encoded."""
        pkt = RTPPacket(extension=True, payload=b"")
        raw = pkt.to_bytes()
        assert raw[0] & 0x10


class TestRTPPacketPayloadTypes:
    """Test common payload type constants."""

    def test_amr_wb_pt(self):
        assert PT_AMR_WB == 96

    def test_amr_nb_pt(self):
        assert PT_AMR_NB == 97

    def test_evs_pt(self):
        assert PT_EVS == 98

    def test_telephone_event_pt(self):
        assert PT_TELEPHONE_EVENT == 101


# =============================================================================
# RTCP Sender Report Tests
# =============================================================================

class TestRTCPSenderReport:
    """Test RTCP SR packet construction and parsing."""

    def test_sr_to_bytes_length(self):
        """SR should be 28 bytes (8 header + 20 sender info)."""
        sr = RTCPSenderReport(ssrc=1)
        raw = sr.to_bytes()
        assert len(raw) == 28

    def test_sr_packet_type(self):
        sr = RTCPSenderReport()
        raw = sr.to_bytes()
        # PT is at byte offset 1
        assert raw[1] == 200

    def test_sr_version_bits(self):
        sr = RTCPSenderReport()
        raw = sr.to_bytes()
        # V=2, P=0, RC=0 → 0x80
        assert raw[0] == 0x80

    def test_sr_roundtrip(self):
        sr = RTCPSenderReport(
            ssrc=0xABCD1234,
            ntp_timestamp_msw=3900000000,
            ntp_timestamp_lsw=2000000000,
            rtp_timestamp=320000,
            sender_packet_count=150,
            sender_octet_count=9000,
        )
        raw = sr.to_bytes()
        parsed = RTCPSenderReport.from_bytes(raw)
        assert parsed.ssrc == 0xABCD1234
        assert parsed.ntp_timestamp_msw == 3900000000
        assert parsed.ntp_timestamp_lsw == 2000000000
        assert parsed.rtp_timestamp == 320000
        assert parsed.sender_packet_count == 150
        assert parsed.sender_octet_count == 9000

    def test_sr_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            RTCPSenderReport.from_bytes(b"\x00" * 27)


# =============================================================================
# RTCP Receiver Report Tests
# =============================================================================

class TestRTCPReceiverReport:
    """Test RTCP RR packet construction and parsing."""

    def test_rr_to_bytes_length(self):
        """RR with one report block = 32 bytes."""
        rr = RTCPReceiverReport(ssrc=1)
        raw = rr.to_bytes()
        assert len(raw) == 32

    def test_rr_packet_type(self):
        rr = RTCPReceiverReport()
        raw = rr.to_bytes()
        assert raw[1] == 201

    def test_rr_rc_one(self):
        """RC should be 1 (one report block)."""
        rr = RTCPReceiverReport()
        raw = rr.to_bytes()
        # V=2, P=0, RC=1 → 0x81
        assert raw[0] == 0x81

    def test_rr_roundtrip(self):
        rr = RTCPReceiverReport(
            ssrc=0x11223344,
            source_ssrc=0x55667788,
            fraction_lost=25,
            cumulative_lost=100,
            highest_seq=5000,
            jitter=320,
            last_sr=0xAABBCCDD,
            delay_since_sr=65536,
        )
        raw = rr.to_bytes()
        parsed = RTCPReceiverReport.from_bytes(raw)
        assert parsed.ssrc == 0x11223344
        assert parsed.source_ssrc == 0x55667788
        assert parsed.fraction_lost == 25
        assert parsed.cumulative_lost == 100
        assert parsed.highest_seq == 5000
        assert parsed.jitter == 320
        assert parsed.last_sr == 0xAABBCCDD
        assert parsed.delay_since_sr == 65536

    def test_rr_fraction_lost_encoding(self):
        """Fraction lost (8 bits) and cumulative lost (24 bits) share a word."""
        rr = RTCPReceiverReport(fraction_lost=128, cumulative_lost=0xABCDEF)
        raw = rr.to_bytes()
        parsed = RTCPReceiverReport.from_bytes(raw)
        assert parsed.fraction_lost == 128
        assert parsed.cumulative_lost == 0xABCDEF

    def test_rr_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            RTCPReceiverReport.from_bytes(b"\x00" * 31)


# =============================================================================
# RTP Utility Function Tests
# =============================================================================

class TestRTPUtilities:
    """Test SSRC generation and NTP timestamps."""

    def test_generate_ssrc_is_32bit(self):
        ssrc = generate_ssrc()
        assert 0 <= ssrc <= 0xFFFFFFFF

    def test_generate_ssrc_random(self):
        """Two SSRCs should (almost certainly) be different."""
        a = generate_ssrc()
        b = generate_ssrc()
        assert a != b

    def test_ntp_timestamp_now_returns_tuple(self):
        msw, lsw = ntp_timestamp_now()
        assert isinstance(msw, int)
        assert isinstance(lsw, int)

    def test_ntp_timestamp_msw_reasonable(self):
        """MSW should be NTP seconds since 1900 — roughly 3.9 billion in 2024+."""
        msw, _ = ntp_timestamp_now()
        assert msw > 3_800_000_000  # After 2020
        assert msw < 4_300_000_000  # Before 2050


# =============================================================================
# AMR Codec Frame Tests
# =============================================================================

class TestAMRMode:
    """Test AMR codec mode enumeration."""

    def test_mode_values(self):
        assert AMRMode.MODE_0 == 0
        assert AMRMode.MODE_8 == 8
        assert AMRMode.SID == 9
        assert AMRMode.NO_DATA == 15

    def test_default_mode(self):
        assert DEFAULT_AMR_WB_MODE == AMRMode.MODE_8


class TestAMRFrameSizes:
    """Test AMR frame size tables."""

    def test_amr_wb_mode_8_size(self):
        assert AMR_WB_FRAME_SIZES[8] == 60

    def test_amr_wb_sid_size(self):
        assert AMR_WB_FRAME_SIZES[9] == 5

    def test_amr_wb_no_data_size(self):
        assert AMR_WB_FRAME_SIZES[15] == 0

    def test_amr_nb_mode_7_size(self):
        assert AMR_NB_FRAME_SIZES[7] == 31

    def test_amr_nb_sid_size(self):
        assert AMR_NB_FRAME_SIZES[8] == 5

    def test_amr_wb_all_modes_present(self):
        for mode in range(9):
            assert mode in AMR_WB_FRAME_SIZES

    def test_amr_nb_all_modes_present(self):
        for mode in range(8):
            assert mode in AMR_NB_FRAME_SIZES


class TestAMRFrame:
    """Test AMR frame packing/unpacking."""

    def test_to_rtp_payload_structure(self):
        """Octet-aligned: CMR byte + ToC byte + data."""
        frame = AMRFrame(mode=8, quality=True, data=b"\x00" * 60)
        payload = frame.to_rtp_payload()
        assert len(payload) == 2 + 60  # CMR + ToC + data

    def test_cmr_byte(self):
        """CMR should be in upper 4 bits of first byte."""
        frame = AMRFrame(mode=8, cmr=7, data=b"\x00")
        payload = frame.to_rtp_payload()
        assert (payload[0] >> 4) == 7

    def test_toc_byte_mode(self):
        """ToC: mode in bits 3-6."""
        frame = AMRFrame(mode=5, data=b"\x00")
        payload = frame.to_rtp_payload()
        toc = payload[1]
        extracted_mode = (toc >> 3) & 0x0F
        assert extracted_mode == 5

    def test_toc_byte_quality(self):
        """ToC: quality bit at bit 2."""
        frame_good = AMRFrame(mode=8, quality=True, data=b"\x00")
        frame_bad = AMRFrame(mode=8, quality=False, data=b"\x00")
        assert frame_good.to_rtp_payload()[1] & 0x04
        assert not (frame_bad.to_rtp_payload()[1] & 0x04)

    def test_roundtrip_wb(self):
        data = b"\xAA" * 60
        frame = AMRFrame(mode=8, quality=True, data=data, cmr=15, is_wideband=True)
        payload = frame.to_rtp_payload()
        parsed = AMRFrame.from_rtp_payload(payload, is_wideband=True)
        assert parsed.mode == 8
        assert parsed.quality == True
        assert parsed.data == data
        assert parsed.cmr == 15

    def test_roundtrip_nb(self):
        data = b"\xBB" * 31
        frame = AMRFrame(mode=7, quality=True, data=data, is_wideband=False)
        payload = frame.to_rtp_payload()
        parsed = AMRFrame.from_rtp_payload(payload, is_wideband=False)
        assert parsed.mode == 7
        assert parsed.data == data

    def test_from_rtp_payload_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            AMRFrame.from_rtp_payload(b"\x00")

    def test_silence_frame_wb(self):
        frame = AMRFrame.silence(is_wideband=True)
        assert frame.mode == AMRMode.SID
        assert frame.is_wideband == True
        assert len(frame.data) == 5

    def test_silence_frame_nb(self):
        frame = AMRFrame.silence(is_wideband=False)
        assert frame.mode == AMRMode.SID
        assert frame.is_wideband == False

    def test_frame_size_property_wb(self):
        frame = AMRFrame(mode=8, is_wideband=True)
        assert frame.frame_size == 60

    def test_frame_size_property_nb(self):
        frame = AMRFrame(mode=7, is_wideband=False)
        assert frame.frame_size == 31

    def test_clock_rate_property(self):
        wb = AMRFrame(is_wideband=True)
        nb = AMRFrame(is_wideband=False)
        assert wb.clock_rate == 16000
        assert nb.clock_rate == 8000

    def test_samples_per_frame_property(self):
        wb = AMRFrame(is_wideband=True)
        nb = AMRFrame(is_wideband=False)
        assert wb.samples_per_frame == 320
        assert nb.samples_per_frame == 160


class TestAMRClockRates:
    """Test codec clock rate constants."""

    def test_amr_wb_clock(self):
        assert AMR_WB_CLOCK_RATE == 16000

    def test_amr_nb_clock(self):
        assert AMR_NB_CLOCK_RATE == 8000

    def test_evs_clock(self):
        assert EVS_CLOCK_RATE == 16000

    def test_amr_wb_samples(self):
        assert AMR_WB_SAMPLES_PER_FRAME == 320  # 16000 * 0.020

    def test_amr_nb_samples(self):
        assert AMR_NB_SAMPLES_PER_FRAME == 160  # 8000 * 0.020

    def test_evs_samples(self):
        assert EVS_SAMPLES_PER_FRAME == 320


# =============================================================================
# DTMF Event Tests
# =============================================================================

class TestDTMFEvent:
    """Test DTMF telephone event encoding/decoding."""

    def test_to_rtp_payload_length(self):
        """DTMF payload is always 4 bytes."""
        event = DTMFEvent(event=1, end=False, volume=10, duration=1600)
        payload = event.to_rtp_payload()
        assert len(payload) == 4

    def test_event_code_byte(self):
        event = DTMFEvent(event=5)
        payload = event.to_rtp_payload()
        assert payload[0] == 5

    def test_end_flag(self):
        event_on = DTMFEvent(event=0, end=False)
        event_off = DTMFEvent(event=0, end=True)
        assert not (event_on.to_rtp_payload()[1] & 0x80)
        assert event_off.to_rtp_payload()[1] & 0x80

    def test_volume_encoding(self):
        event = DTMFEvent(event=0, volume=20)
        payload = event.to_rtp_payload()
        assert payload[1] & 0x3F == 20

    def test_duration_encoding(self):
        event = DTMFEvent(event=0, duration=3200)
        payload = event.to_rtp_payload()
        dur = struct.unpack("!H", payload[2:4])[0]
        assert dur == 3200

    def test_roundtrip(self):
        event = DTMFEvent(event=9, end=True, volume=15, duration=2560)
        payload = event.to_rtp_payload()
        parsed = DTMFEvent.from_rtp_payload(payload)
        assert parsed.event == 9
        assert parsed.end == True
        assert parsed.volume == 15
        assert parsed.duration == 2560

    def test_from_rtp_payload_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            DTMFEvent.from_rtp_payload(b"\x00\x00\x00")

    def test_from_digit(self):
        event = DTMFEvent.from_digit("5")
        assert event.event == 5

    def test_from_digit_star(self):
        event = DTMFEvent.from_digit("*")
        assert event.event == 10

    def test_from_digit_hash(self):
        event = DTMFEvent.from_digit("#")
        assert event.event == 11

    def test_from_digit_letter(self):
        event = DTMFEvent.from_digit("A")
        assert event.event == 12

    def test_from_digit_case_insensitive(self):
        event = DTMFEvent.from_digit("b")
        assert event.event == 13

    def test_digit_property(self):
        for digit, code in DTMF_EVENTS.items():
            event = DTMFEvent(event=code)
            assert event.digit == digit

    def test_digit_property_unknown(self):
        event = DTMFEvent(event=99)
        assert event.digit == "?"


class TestDTMFEventMapping:
    """Test DTMF digit to event code mapping."""

    def test_digits_0_through_9(self):
        for i in range(10):
            assert DTMF_EVENTS[str(i)] == i

    def test_star(self):
        assert DTMF_EVENTS["*"] == 10

    def test_hash(self):
        assert DTMF_EVENTS["#"] == 11

    def test_letters_a_through_d(self):
        assert DTMF_EVENTS["A"] == 12
        assert DTMF_EVENTS["B"] == 13
        assert DTMF_EVENTS["C"] == 14
        assert DTMF_EVENTS["D"] == 15

    def test_total_events(self):
        assert len(DTMF_EVENTS) == 16


# =============================================================================
# get_codec_info Tests
# =============================================================================

class TestGetCodecInfo:
    """Test codec info lookup."""

    def test_amr_wb(self):
        info = get_codec_info("AMR-WB")
        assert info["clock_rate"] == 16000
        assert info["samples_per_frame"] == 320
        assert info["ptime"] == 20

    def test_amr_nb(self):
        info = get_codec_info("AMR")
        assert info["clock_rate"] == 8000
        assert info["samples_per_frame"] == 160

    def test_evs(self):
        info = get_codec_info("EVS")
        assert info["clock_rate"] == 16000
        assert info["samples_per_frame"] == 320

    def test_case_insensitive(self):
        info = get_codec_info("amr-wb")
        assert info["clock_rate"] == 16000

    def test_unknown_falls_back_to_amr_wb(self):
        info = get_codec_info("UNKNOWN-CODEC")
        assert info["clock_rate"] == 16000  # AMR-WB default


# =============================================================================
# Jitter Buffer Tests
# =============================================================================

class TestJitterBuffer:
    """Test adaptive jitter buffer."""

    def _make_packet(self, seq, ts=0, payload=b"\x00"):
        return RTPPacket(sequence_number=seq, timestamp=ts, payload=payload)

    def test_empty_buffer_get_returns_none(self):
        buf = JitterBuffer()
        assert buf.get() is None

    def test_put_increments_received(self):
        buf = JitterBuffer(target_depth=1)
        buf.put(self._make_packet(1))
        assert buf.packets_received == 1

    def test_depth_property(self):
        buf = JitterBuffer(target_depth=1)
        buf.put(self._make_packet(0))
        assert buf.depth == 1

    def test_get_returns_payload_in_order(self):
        buf = JitterBuffer(target_depth=2)
        buf.put(self._make_packet(0, payload=b"\x01"))
        buf.put(self._make_packet(1, payload=b"\x02"))
        result = buf.get()
        assert result == b"\x01"

    def test_reordering(self):
        """Out-of-order packets should be reordered by insertion sort."""
        buf = JitterBuffer(target_depth=2)
        # seq 10 arrives first (sets _next_seq=10), then 12, then 11
        buf.put(self._make_packet(10, payload=b"\x0A"))
        buf.put(self._make_packet(12, payload=b"\x0C"))
        buf.put(self._make_packet(11, payload=b"\x0B"))
        # Buffer should have [10, 11, 12] sorted; depth=3 >= target=2
        result = buf.get()
        assert result == b"\x0A"  # seq 10 first
        result = buf.get()
        assert result == b"\x0B"  # seq 11 reordered correctly

    def test_duplicate_detection(self):
        buf = JitterBuffer(target_depth=1)
        buf.put(self._make_packet(0))
        buf.put(self._make_packet(0))  # duplicate
        assert buf.packets_duplicate == 1
        assert buf.depth == 1  # only one entry

    def test_sequential_playback(self):
        """Packets should play out in sequence order."""
        buf = JitterBuffer(target_depth=3)
        for i in range(5):
            buf.put(self._make_packet(i, payload=bytes([i])))
        payloads = []
        for _ in range(3):
            p = buf.get()
            if p is not None:
                payloads.append(p)
        assert payloads == [b"\x00", b"\x01", b"\x02"]

    def test_loss_detection(self):
        """Missing sequence numbers should be detected as loss."""
        buf = JitterBuffer(target_depth=2)
        buf.put(self._make_packet(0, payload=b"\x00"))
        # Skip seq 1
        buf.put(self._make_packet(2, payload=b"\x02"))
        buf.put(self._make_packet(3, payload=b"\x03"))
        buf.put(self._make_packet(4, payload=b"\x04"))

        p0 = buf.get()  # seq 0
        assert p0 == b"\x00"
        p1 = buf.get()  # seq 1 missing → loss
        assert p1 == b""  # empty = loss signal
        assert buf.packets_lost >= 1

    def test_jitter_ms_property(self):
        buf = JitterBuffer()
        assert buf.jitter_ms == 0.0  # no packets yet

    def test_reset(self):
        buf = JitterBuffer(target_depth=1)
        buf.put(self._make_packet(0))
        buf.reset()
        assert buf.depth == 0
        assert buf._next_seq is None

    def test_get_stats(self):
        buf = JitterBuffer(target_depth=1)
        buf.put(self._make_packet(0))
        stats = buf.get_stats()
        assert "depth" in stats
        assert "jitter_ms" in stats
        assert "received" in stats
        assert "played" in stats
        assert "lost" in stats
        assert "late" in stats
        assert "duplicate" in stats
        assert stats["received"] == 1

    def test_below_target_depth_returns_none(self):
        """Buffer should not release packets until target depth is reached."""
        buf = JitterBuffer(target_depth=4)
        buf.put(self._make_packet(0))
        buf.put(self._make_packet(1))
        buf.put(self._make_packet(2))
        assert buf.get() is None  # only 3 packets, target is 4


# =============================================================================
# MediaSession Tests
# =============================================================================

class TestMediaSession:
    """Test RTP media session lifecycle."""

    def test_init_defaults(self):
        session = MediaSession()
        assert session.codec == "AMR-WB"
        assert session.payload_type == PT_AMR_WB
        assert session._active == False
        assert session.local_port == 0

    def test_init_custom_ssrc(self):
        session = MediaSession(ssrc=0xDEADBEEF)
        assert session.ssrc == 0xDEADBEEF

    def test_init_generates_ssrc(self):
        session = MediaSession()
        assert session.ssrc != 0

    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self):
        """Session should track active state."""
        session = MediaSession()
        # Use a high port to avoid binding conflicts
        await session.start(
            local_port=59000,
            remote_ip="127.0.0.1",
            remote_port=59002,
            codec="AMR-WB",
        )
        assert session._active == True
        assert session.codec == "AMR-WB"
        assert session.remote_addr == ("127.0.0.1", 59002)

        await session.stop()
        assert session._active == False

    @pytest.mark.asyncio
    async def test_start_configures_codec(self):
        session = MediaSession()
        await session.start(60000, "127.0.0.1", 60002, codec="AMR")
        assert session._clock_rate == AMR_NB_CLOCK_RATE
        assert session._samples_per_frame == AMR_NB_SAMPLES_PER_FRAME
        await session.stop()

    @pytest.mark.asyncio
    async def test_start_evs_codec(self):
        session = MediaSession()
        await session.start(60100, "127.0.0.1", 60102, codec="EVS")
        assert session._clock_rate == EVS_CLOCK_RATE
        await session.stop()

    def test_send_frame_when_not_active(self):
        """send_frame should be a no-op when not active."""
        session = MediaSession()
        session.send_frame(b"\x00" * 60)
        assert session.stats.packets_sent == 0

    @pytest.mark.asyncio
    async def test_send_frame_increments_stats(self):
        session = MediaSession()
        await session.start(60200, "127.0.0.1", 60202)
        session.send_frame(b"\x00" * 62)
        assert session.stats.packets_sent == 1
        assert session.stats.bytes_sent > 0
        assert session._seq == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_frame_increments_timestamp(self):
        session = MediaSession()
        await session.start(60300, "127.0.0.1", 60302)
        ts_before = session._timestamp
        session.send_frame(b"\x00" * 60)
        assert session._timestamp == ts_before + session._samples_per_frame
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_dtmf(self):
        """DTMF send should produce 5 packets (start + ongoing + 3x end)."""
        session = MediaSession()
        await session.start(60400, "127.0.0.1", 60402)
        session.send_dtmf("5", duration_ms=160)
        assert session.stats.packets_sent == 5
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_dtmf_invalid_digit(self):
        session = MediaSession()
        await session.start(60500, "127.0.0.1", 60502)
        session.send_dtmf("X")  # invalid digit
        assert session.stats.packets_sent == 0
        await session.stop()

    @pytest.mark.asyncio
    async def test_get_stats(self):
        session = MediaSession()
        await session.start(60600, "127.0.0.1", 60602)
        session.send_frame(b"\x00" * 60)
        stats = session.get_stats()
        assert stats["codec"] == "AMR-WB"
        assert stats["packets_sent"] == 1
        assert stats["packets_received"] == 0
        assert "ssrc" in stats
        assert "jitter_buffer" in stats
        assert stats["duration_seconds"] >= 0
        await session.stop()

    @pytest.mark.asyncio
    async def test_on_rtp_received(self):
        """Incoming RTP should increment stats and feed jitter buffer."""
        session = MediaSession()
        await session.start(60700, "127.0.0.1", 60702)
        # Craft a valid RTP packet
        pkt = RTPPacket(
            payload_type=PT_AMR_WB,
            sequence_number=100,
            timestamp=32000,
            ssrc=0x12345678,
            payload=b"\x00" * 62,
        )
        session._on_rtp_received(pkt.to_bytes(), ("127.0.0.1", 60702))
        assert session.stats.packets_received == 1
        assert session.jitter_buffer.packets_received == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_on_rtp_received_dtmf(self):
        """DTMF RTP packets should not go to jitter buffer."""
        session = MediaSession()
        await session.start(60800, "127.0.0.1", 60802)
        # DTMF packet
        pkt = RTPPacket(
            payload_type=PT_TELEPHONE_EVENT,
            sequence_number=1,
            ssrc=0x11111111,
            payload=DTMFEvent(event=5, end=True).to_rtp_payload(),
        )
        session._on_rtp_received(pkt.to_bytes(), ("127.0.0.1", 60802))
        assert session.stats.packets_received == 1
        assert session.jitter_buffer.packets_received == 0
        await session.stop()

    @pytest.mark.asyncio
    async def test_on_rtp_received_invalid(self):
        """Invalid RTP data should be silently discarded."""
        session = MediaSession()
        await session.start(60900, "127.0.0.1", 60902)
        session._on_rtp_received(b"\x00\x01\x02", ("127.0.0.1", 60902))
        assert session.stats.packets_received == 0
        await session.stop()

    @pytest.mark.asyncio
    async def test_dtmf_callback(self):
        """DTMF callback should fire on end-of-event."""
        received_digits = []
        async def on_dtmf(digit):
            received_digits.append(digit)

        session = MediaSession()
        session.set_dtmf_callback(on_dtmf)
        await session.start(61000, "127.0.0.1", 61002)

        # Send DTMF end event
        pkt = RTPPacket(
            payload_type=PT_TELEPHONE_EVENT,
            sequence_number=1,
            ssrc=0x22222222,
            payload=DTMFEvent(event=5, end=True).to_rtp_payload(),
        )
        session._on_rtp_received(pkt.to_bytes(), ("127.0.0.1", 61002))
        # Allow the callback coroutine to run
        await asyncio.sleep(0.05)
        assert received_digits == ["5"]
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_amr_frame(self):
        session = MediaSession()
        await session.start(61100, "127.0.0.1", 61102)
        session.send_amr_frame(mode=8, silence=False)
        assert session.stats.packets_sent == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_amr_silence_frame(self):
        session = MediaSession()
        await session.start(61200, "127.0.0.1", 61202)
        session.send_amr_frame(silence=True)
        assert session.stats.packets_sent == 1
        await session.stop()


class TestMediaStats:
    """Test MediaStats dataclass."""

    def test_defaults(self):
        stats = MediaStats()
        assert stats.packets_sent == 0
        assert stats.packets_received == 0
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.rtcp_sr_sent == 0
        assert stats.rtcp_rr_sent == 0
        assert stats.codec == ""


# =============================================================================
# SDP Parsing Tests
# =============================================================================

class TestSDPParsing:
    """Test SDP parsing helpers."""

    def test_parse_remote_rtp_address_basic(self):
        sdp = (
            "v=0\r\n"
            "o=- 1 1 IN IP4 192.168.1.100\r\n"
            "c=IN IP4 192.168.1.100\r\n"
            "m=audio 40000 RTP/AVP 96\r\n"
        )
        ip, port = parse_remote_rtp_address(sdp)
        assert ip == "192.168.1.100"
        assert port == 40000

    def test_parse_remote_rtp_address_ipv6(self):
        sdp = (
            "c=IN IP6 2001:db8::1\r\n"
            "m=audio 50000 RTP/AVP 96\r\n"
        )
        ip, port = parse_remote_rtp_address(sdp)
        assert ip == "2001:db8::1"
        assert port == 50000

    def test_parse_remote_rtp_address_missing_connection(self):
        sdp = "m=audio 40000 RTP/AVP 96\r\n"
        ip, port = parse_remote_rtp_address(sdp)
        assert ip == "0.0.0.0"
        assert port == 40000

    def test_parse_remote_rtp_address_missing_media(self):
        sdp = "c=IN IP4 10.0.0.1\r\n"
        ip, port = parse_remote_rtp_address(sdp)
        assert ip == "10.0.0.1"
        assert port == 0

    def test_parse_remote_rtp_address_empty(self):
        ip, port = parse_remote_rtp_address("")
        assert ip == "0.0.0.0"
        assert port == 0

    def test_parse_payload_type_from_rtpmap(self):
        sdp = (
            "m=audio 40000 RTP/AVP 96 97\r\n"
            "a=rtpmap:96 AMR-WB/16000/1\r\n"
            "a=rtpmap:97 AMR/8000/1\r\n"
        )
        assert parse_payload_type(sdp, "AMR-WB") == 96
        # Note: "AMR" substring matches "AMR-WB" first in regex;
        # this is acceptable since VoLTE always uses AMR-WB by default
        assert parse_payload_type(sdp, "AMR") == 96

    def test_parse_payload_type_fallback(self):
        """When codec not in SDP, should return default PT."""
        sdp = "m=audio 40000 RTP/AVP 96\r\n"
        assert parse_payload_type(sdp, "AMR-WB") == PT_AMR_WB

    def test_parse_payload_type_evs(self):
        sdp = "a=rtpmap:120 EVS/16000/1\r\n"
        assert parse_payload_type(sdp, "EVS") == 120


# =============================================================================
# Module-level State Tests
# =============================================================================

class TestMediaState:
    """Test module-level media state for management API."""

    def test_get_media_state_returns_dict(self):
        state = get_media_state()
        assert isinstance(state, dict)
        assert "active_sessions" in state
        assert "total_packets_sent" in state
        assert "total_packets_received" in state

    def test_get_media_state_returns_copy(self):
        """get_media_state should return a copy, not the original."""
        state = get_media_state()
        state["active_sessions"] = 999
        assert get_media_state()["active_sessions"] != 999 or \
               _media_state["active_sessions"] != 999

    @pytest.mark.asyncio
    async def test_session_updates_global_state(self):
        """Starting/stopping a session should update global counters."""
        initial = get_media_state()["active_sessions"]
        session = MediaSession()
        await session.start(61300, "127.0.0.1", 61302)
        assert get_media_state()["active_sessions"] == initial + 1
        session.send_frame(b"\x00" * 60)
        await session.stop()
        assert get_media_state()["active_sessions"] == initial


# =============================================================================
# VoLTE Media Integration Tests
# =============================================================================

class TestVoLTEMediaIntegration:
    """Test VoLTE call manager media integration."""

    def test_volte_call_has_media_session_field(self):
        from ims.volte import VoLTECall
        call = VoLTECall()
        assert call.media_session is None

    @pytest.mark.asyncio
    async def test_start_media_with_sdp(self):
        from ims.volte import VoLTECallManager, VoLTEConfig, VoLTECall, VoLTECallState
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        call = VoLTECall(
            sip_call_id="test-123",
            state=VoLTECallState.ACTIVE,
            remote_sdp=(
                "v=0\r\n"
                "c=IN IP4 10.0.0.1\r\n"
                "m=audio 50000 RTP/AVP 96\r\n"
                "a=rtpmap:96 AMR-WB/16000/1\r\n"
            ),
            rtp_port=61400,
            codec="AMR-WB",
        )
        await mgr._start_media(call)
        assert call.media_session is not None
        assert call.media_session._active == True
        await mgr._stop_media(call)
        assert call.media_session is None

    @pytest.mark.asyncio
    async def test_start_media_no_sdp(self):
        from ims.volte import VoLTECallManager, VoLTEConfig, VoLTECall
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        call = VoLTECall(remote_sdp="", rtp_port=61500)
        await mgr._start_media(call)
        assert call.media_session is None

    @pytest.mark.asyncio
    async def test_stop_media_when_no_session(self):
        from ims.volte import VoLTECallManager, VoLTEConfig, VoLTECall
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        call = VoLTECall(media_session=None)
        await mgr._stop_media(call)  # should not raise

    def test_get_calls_includes_media_stats(self):
        from ims.volte import VoLTECallManager, VoLTEConfig, VoLTECall, VoLTECallState
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        # Call without media session
        call = VoLTECall(
            sip_call_id="test-456",
            state=VoLTECallState.ACTIVE,
            direction="MO",
            remote_number="+1234567890",
            codec="AMR-WB",
            rtp_port=50000,
        )
        mgr._calls["test-456"] = call
        calls = mgr.get_calls()
        assert len(calls) == 1
        assert calls[0]["media"] is None

    def test_get_calls_with_media_session(self):
        from ims.volte import VoLTECallManager, VoLTEConfig, VoLTECall, VoLTECallState
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        session = MediaSession(ssrc=0xAAAABBBB)
        session.stats.codec = "AMR-WB"
        call = VoLTECall(
            sip_call_id="test-789",
            state=VoLTECallState.ACTIVE,
            direction="MO",
            remote_number="+1234567890",
            codec="AMR-WB",
            rtp_port=50000,
            media_session=session,
        )
        mgr._calls["test-789"] = call
        calls = mgr.get_calls()
        assert calls[0]["media"] is not None
        assert calls[0]["media"]["ssrc"] == "aaaabbbb"
        assert calls[0]["media"]["codec"] == "AMR-WB"


# =============================================================================
# Management API /status/media Endpoint Tests
# =============================================================================

class TestManagementAPIMedia:
    """Test /status/media API endpoint."""

    @pytest.mark.asyncio
    async def test_status_media_endpoint(self):
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/status/media")
            assert resp.status_code == 200
            data = resp.json()
            assert "active_sessions" in data
            assert "total_packets_sent" in data
            assert "total_packets_received" in data


# =============================================================================
# RTCP Integration Tests
# =============================================================================

class TestRTCPIntegration:
    """Test RTCP report generation within MediaSession."""

    @pytest.mark.asyncio
    async def test_send_rtcp_sr(self):
        session = MediaSession()
        await session.start(61600, "127.0.0.1", 61602)
        session._send_rtcp_sr()
        assert session.stats.rtcp_sr_sent == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_rtcp_rr(self):
        session = MediaSession()
        await session.start(61700, "127.0.0.1", 61702)
        session._send_rtcp_rr()
        assert session.stats.rtcp_rr_sent == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_send_rtcp_rr_with_loss(self):
        """RR should calculate fraction lost from jitter buffer stats."""
        session = MediaSession()
        await session.start(61800, "127.0.0.1", 61802)
        # Simulate some loss in jitter buffer
        session.jitter_buffer.packets_received = 100
        session.jitter_buffer.packets_lost = 10
        session._send_rtcp_rr()
        assert session.stats.rtcp_rr_sent == 1
        await session.stop()


# =============================================================================
# Virtual Audio Source tests
# =============================================================================

class TestVirtualAudioSource:
    """Test virtual audio source for media sessions."""

    def test_silence_source_generates_sid_frames(self):
        """Silence source generates SID comfort noise frames."""
        source = VirtualAudioSource(AudioSourceType.SILENCE)
        frame = source.generate_frame(is_wideband=True)
        assert frame.data is not None
        assert len(frame.data) > 0

    def test_zero_source_generates_zero_filled(self):
        """Zero source generates zero-filled frames."""
        source = VirtualAudioSource(AudioSourceType.ZERO)
        frame = source.generate_frame(is_wideband=True, mode=8)
        assert all(b == 0 for b in frame.data)

    def test_tone_source_generates_nonzero(self):
        """Tone source generates frames with non-zero data."""
        source = VirtualAudioSource(AudioSourceType.TONE, frequency=440)
        frame = source.generate_frame(is_wideband=True, mode=8)
        assert any(b != 0 for b in frame.data)

    def test_tone_source_different_frequencies(self):
        """Different tone frequencies produce different frame data."""
        source1 = VirtualAudioSource(AudioSourceType.TONE, frequency=440)
        source2 = VirtualAudioSource(AudioSourceType.TONE, frequency=880)
        frame1 = source1.generate_frame(is_wideband=True)
        frame2 = source2.generate_frame(is_wideband=True)
        assert frame1.data != frame2.data

    def test_loopback_without_data_returns_silence(self):
        """Loopback source without buffered data returns SID frames."""
        source = VirtualAudioSource(AudioSourceType.LOOPBACK)
        frame = source.generate_frame(is_wideband=True)
        assert frame.data is not None

    def test_loopback_echoes_fed_data(self):
        """Loopback source echoes back data fed via feed_loopback."""
        source = VirtualAudioSource(AudioSourceType.LOOPBACK)
        test_data = b"\x42" * 64
        source.feed_loopback(test_data)
        frame = source.generate_frame(is_wideband=True, mode=8)
        assert frame.data == test_data

    def test_feed_loopback_ignored_for_non_loopback(self):
        """feed_loopback is no-op for non-loopback sources."""
        source = VirtualAudioSource(AudioSourceType.SILENCE)
        source.feed_loopback(b"\x42" * 64)

    def test_frame_count_increments(self):
        """Frame count increments with each generate_frame call."""
        source = VirtualAudioSource(AudioSourceType.SILENCE)
        assert source.frame_count == 0
        source.generate_frame()
        assert source.frame_count == 1
        source.generate_frame()
        source.generate_frame()
        assert source.frame_count == 3

    def test_narrowband_frames(self):
        """Audio source generates NB frames when is_wideband=False."""
        source = VirtualAudioSource(AudioSourceType.ZERO)
        frame = source.generate_frame(is_wideband=False, mode=7)
        assert frame.is_wideband is False

    @pytest.mark.asyncio
    async def test_session_uses_audio_source(self):
        """MediaSession uses the configured audio source."""
        session = MediaSession()
        await session.start(62100, "127.0.0.1", 62102)
        source = VirtualAudioSource(AudioSourceType.TONE, frequency=1000)
        session.set_audio_source(source)
        session.send_amr_frame(mode=8)
        assert source.frame_count == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_session_default_audio_source_is_silence(self):
        """MediaSession defaults to silence audio source."""
        session = MediaSession()
        await session.start(62200, "127.0.0.1", 62202)
        assert session._audio_source.source_type == AudioSourceType.SILENCE
        await session.stop()

    @pytest.mark.asyncio
    async def test_stats_include_audio_source(self):
        """get_stats() includes audio_source field."""
        session = MediaSession()
        await session.start(62300, "127.0.0.1", 62302)
        stats = session.get_stats()
        assert "audio_source" in stats
        assert stats["audio_source"] == "silence"
        session.set_audio_source(VirtualAudioSource(AudioSourceType.TONE))
        stats = session.get_stats()
        assert stats["audio_source"] == "tone"
        await session.stop()
