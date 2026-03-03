"""
VoLTE codec frame handling.

Handles AMR-WB, AMR-NB, and EVS codec frame packing/unpacking
for RTP transport, plus DTMF event generation per RFC 4733.

AMR-WB (Adaptive Multi-Rate Wideband, 3GPP TS 26.201):
  16 kHz sample rate, frame size 20 ms = 320 samples
  9 codec modes (0-8): 6.60 - 23.85 kbps
  Bandwidth-efficient and octet-aligned packing modes
  For VoLTE, octet-aligned mode is standard (RFC 4867)

AMR-NB (Adaptive Multi-Rate, 3GPP TS 26.101):
  8 kHz sample rate, frame size 20 ms = 160 samples
  8 codec modes (0-7): 4.75 - 12.20 kbps

EVS (Enhanced Voice Services, 3GPP TS 26.445):
  Supports 8/16/32/48 kHz, typical VoLTE uses 16 kHz
  Frame size 20 ms

DTMF (RFC 4733):
  Telephone events carried as named events in RTP
  Event codes: 0-9 for digits, 10=*, 11=#, 12-15=A-D

Reference: RFC 4867 (AMR/AMR-WB RTP), RFC 4733 (DTMF), 3GPP TS 26.114
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


class AMRMode(IntEnum):
    """AMR-WB codec modes (3GPP TS 26.201 Table 2)."""
    MODE_0 = 0    # 6.60 kbps
    MODE_1 = 1    # 8.85 kbps
    MODE_2 = 2    # 12.65 kbps
    MODE_3 = 3    # 14.25 kbps
    MODE_4 = 4    # 15.85 kbps
    MODE_5 = 5    # 18.25 kbps
    MODE_6 = 6    # 19.85 kbps
    MODE_7 = 7    # 23.05 kbps
    MODE_8 = 8    # 23.85 kbps
    SID = 9       # Comfort noise (1.75 kbps)
    NO_DATA = 15  # No transmission


# AMR-WB frame sizes in bytes per mode (octet-aligned, RFC 4867 Table 2)
AMR_WB_FRAME_SIZES = {
    0: 17, 1: 23, 2: 32, 3: 36, 4: 40,
    5: 46, 6: 50, 7: 58, 8: 60,
    9: 5,   # SID
    15: 0,  # NO_DATA
}

# AMR-NB frame sizes in bytes per mode (octet-aligned, RFC 4867 Table 1)
AMR_NB_FRAME_SIZES = {
    0: 12, 1: 13, 2: 15, 3: 17, 4: 19,
    5: 20, 6: 26, 7: 31,
    8: 5,   # SID
    15: 0,  # NO_DATA
}

# AMR-WB default mode for VoLTE (23.85 kbps — HD Voice)
DEFAULT_AMR_WB_MODE = AMRMode.MODE_8

# AMR clock rates
AMR_WB_CLOCK_RATE = 16000  # 16 kHz
AMR_NB_CLOCK_RATE = 8000   # 8 kHz
EVS_CLOCK_RATE = 16000     # 16 kHz (typical VoLTE)

# Samples per frame (20 ms)
AMR_WB_SAMPLES_PER_FRAME = 320   # 16000 * 0.020
AMR_NB_SAMPLES_PER_FRAME = 160   # 8000 * 0.020
EVS_SAMPLES_PER_FRAME = 320      # 16000 * 0.020

# DTMF event codes (RFC 4733 Section 7)
DTMF_EVENTS = {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
    "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
    "*": 10, "#": 11,
    "A": 12, "B": 13, "C": 14, "D": 15,
}


@dataclass
class AMRFrame:
    """
    An AMR-WB or AMR-NB codec frame in octet-aligned mode.

    Octet-aligned payload (RFC 4867 Section 4.4):
      CMR (4 bits) | reserved (4 bits)
      F(1) | FT(4) | Q(1) | padding(2)
      [frame data bytes]

    CMR: Codec Mode Request
    F: Followed by another frame (0 = last)
    FT: Frame type (= codec mode)
    Q: Quality (1 = good)
    """
    mode: int = DEFAULT_AMR_WB_MODE
    quality: bool = True
    data: bytes = b""
    cmr: int = 15           # 15 = no mode request
    is_wideband: bool = True  # True = AMR-WB, False = AMR-NB

    def to_rtp_payload(self) -> bytes:
        """Pack to RTP payload in octet-aligned mode."""
        # CMR byte: CMR(4) | reserved(4)
        cmr_byte = (self.cmr & 0x0F) << 4

        # ToC byte: F(1) | FT(4) | Q(1) | padding(2)
        toc_byte = (0 << 7) | ((self.mode & 0x0F) << 3) | \
                   (int(self.quality) << 2)

        return bytes([cmr_byte, toc_byte]) + self.data

    @classmethod
    def from_rtp_payload(cls, payload: bytes,
                         is_wideband: bool = True) -> AMRFrame:
        """Unpack from RTP payload (octet-aligned mode)."""
        if len(payload) < 2:
            raise ValueError("AMR payload too short")

        cmr = (payload[0] >> 4) & 0x0F
        mode = (payload[1] >> 3) & 0x0F
        quality = bool(payload[1] & 0x04)
        data = payload[2:]

        return cls(
            mode=mode,
            quality=quality,
            data=data,
            cmr=cmr,
            is_wideband=is_wideband,
        )

    @property
    def frame_size(self) -> int:
        """Expected data size for this mode."""
        table = AMR_WB_FRAME_SIZES if self.is_wideband else AMR_NB_FRAME_SIZES
        return table.get(self.mode, 0)

    @property
    def clock_rate(self) -> int:
        return AMR_WB_CLOCK_RATE if self.is_wideband else AMR_NB_CLOCK_RATE

    @property
    def samples_per_frame(self) -> int:
        return AMR_WB_SAMPLES_PER_FRAME if self.is_wideband \
            else AMR_NB_SAMPLES_PER_FRAME

    @classmethod
    def silence(cls, is_wideband: bool = True) -> AMRFrame:
        """Create a SID (comfort noise) frame."""
        size = 5  # SID frame is always 5 bytes
        return cls(
            mode=AMRMode.SID,
            quality=True,
            data=b"\x00" * size,
            is_wideband=is_wideband,
        )


@dataclass
class DTMFEvent:
    """
    DTMF telephone event (RFC 4733).

    RTP payload format:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     event     |E|R| volume    |          duration             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    event: 0-9 = digits, 10 = *, 11 = #, 12-15 = A-D
    E: End of event flag
    volume: dBm0 (0 = max, 63 = min)
    duration: In timestamp units
    """
    event: int = 0
    end: bool = False
    volume: int = 10        # -10 dBm0 (typical)
    duration: int = 1600    # 100 ms at 16 kHz (or 800 at 8 kHz)

    def to_rtp_payload(self) -> bytes:
        """Pack to 4-byte RTP payload."""
        byte1 = (int(self.end) << 7) | (self.volume & 0x3F)
        return struct.pack("!BBH", self.event & 0xFF, byte1, self.duration)

    @classmethod
    def from_rtp_payload(cls, payload: bytes) -> DTMFEvent:
        """Unpack from 4-byte RTP payload."""
        if len(payload) < 4:
            raise ValueError("DTMF payload too short")
        event, byte1, duration = struct.unpack("!BBH", payload[:4])
        end = bool(byte1 & 0x80)
        volume = byte1 & 0x3F
        return cls(event=event, end=end, volume=volume, duration=duration)

    @classmethod
    def from_digit(cls, digit: str, duration: int = 1600,
                   end: bool = False) -> DTMFEvent:
        """Create a DTMF event from a digit character."""
        event = DTMF_EVENTS.get(digit.upper(), 0)
        return cls(event=event, end=end, duration=duration)

    @property
    def digit(self) -> str:
        """Return the digit character for this event."""
        for d, e in DTMF_EVENTS.items():
            if e == self.event:
                return d
        return "?"


def get_codec_info(codec_name: str) -> dict:
    """Return clock rate and samples-per-frame for a codec."""
    codec_upper = codec_name.upper().replace("-", "").replace("_", "")
    info = {
        "AMRWB": {"clock_rate": AMR_WB_CLOCK_RATE,
                   "samples_per_frame": AMR_WB_SAMPLES_PER_FRAME,
                   "ptime": 20},
        "AMR": {"clock_rate": AMR_NB_CLOCK_RATE,
                "samples_per_frame": AMR_NB_SAMPLES_PER_FRAME,
                "ptime": 20},
        "EVS": {"clock_rate": EVS_CLOCK_RATE,
                "samples_per_frame": EVS_SAMPLES_PER_FRAME,
                "ptime": 20},
    }
    return info.get(codec_upper, info["AMRWB"])
