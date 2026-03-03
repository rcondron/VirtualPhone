"""
SMS PDU encoding and decoding per 3GPP TS 23.040.

Handles:
- SMS-SUBMIT (MO-SMS): Mobile-originated messages sent by the UE
- SMS-DELIVER (MT-SMS): Mobile-terminated messages received by the UE
- RP-DATA wrapper (3GPP TS 24.011): Relay Protocol for SMS over IMS
- GSM 7-bit and UCS-2 text encoding/decoding

The PDU format from Android's RIL contains an SMSC address prefix followed
by the TPDU. For SMS over IMS, the SMSC is not used (SIP routes the message).

Reference: 3GPP TS 23.040, 3GPP TS 24.011, 3GPP TS 24.341
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class TPMessageType(IntEnum):
    """TP-MTI (Message Type Indicator) values."""
    SMS_DELIVER = 0b00
    SMS_SUBMIT = 0b01
    SMS_STATUS_REPORT = 0b10
    SMS_COMMAND = 0b11


class DataCodingScheme(IntEnum):
    """TP-DCS (Data Coding Scheme) values."""
    GSM_7BIT = 0x00
    UCS2 = 0x08
    EIGHT_BIT = 0x04


class TypeOfNumber(IntEnum):
    """Type of Number values for address fields."""
    UNKNOWN = 0
    INTERNATIONAL = 1
    NATIONAL = 2
    NETWORK_SPECIFIC = 3
    SUBSCRIBER = 4
    ALPHANUMERIC = 5
    ABBREVIATED = 6


# GSM 7-bit default alphabet (3GPP TS 23.038)
GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅå"
    "Δ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ"
    " !\"#¤%&'()*+,-./"
    "0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNO"
    "PQRSTUVWXYZÄÖÑÜÀ"
    "¿abcdefghijklmno"
    "pqrstuvwxyzäöñüà"
)

# Reverse mapping for encoding
GSM7_ENCODE = {c: i for i, c in enumerate(GSM7_BASIC) if c != '\x1b'}


@dataclass
class SMSAddress:
    """An SMS address (phone number or alphanumeric)."""
    number: str = ""
    type_of_number: TypeOfNumber = TypeOfNumber.UNKNOWN
    numbering_plan: int = 1  # ISDN/telephone

    @property
    def type_of_address(self) -> int:
        """Build the Type-of-Address byte: 1 | TON(3) | NPI(4)."""
        return 0x80 | (self.type_of_number << 4) | (self.numbering_plan & 0x0F)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple[SMSAddress, int]:
        """
        Parse an address from PDU bytes.

        Returns (address, new_offset).
        """
        addr_len = data[offset]  # Length in digits (semi-octets)
        toa = data[offset + 1]
        ton = TypeOfNumber((toa >> 4) & 0x07)
        npi = toa & 0x0F

        # Number of bytes for the BCD digits
        num_bytes = (addr_len + 1) // 2
        bcd_bytes = data[offset + 2: offset + 2 + num_bytes]

        if ton == TypeOfNumber.ALPHANUMERIC:
            # Decode GSM 7-bit packed string
            number = decode_gsm7(bcd_bytes, addr_len * 4 // 7)
        else:
            # Decode BCD digits
            number = decode_bcd(bcd_bytes, addr_len)

        return cls(number=number, type_of_number=ton, numbering_plan=npi), offset + 2 + num_bytes

    def to_bytes(self) -> bytes:
        """Encode the address to PDU bytes."""
        if self.type_of_number == TypeOfNumber.ALPHANUMERIC:
            encoded = encode_gsm7(self.number)
            addr_len = len(self.number) * 2  # Approximate in semi-octets
            return bytes([addr_len, self.type_of_address]) + encoded

        # Encode as BCD
        digits = self.number.replace("+", "")
        addr_len = len(digits)
        bcd = encode_bcd(digits)
        return bytes([addr_len, self.type_of_address]) + bcd

    @classmethod
    def international(cls, number: str) -> SMSAddress:
        """Create an international format address."""
        clean = number.lstrip("+")
        return cls(number=clean, type_of_number=TypeOfNumber.INTERNATIONAL)


@dataclass
class SMSSubmit:
    """
    SMS-SUBMIT TPDU (Mobile Originated).

    Sent by the UE to the network to deliver a message.
    """
    message_ref: int = 0
    destination: SMSAddress = field(default_factory=SMSAddress)
    protocol_id: int = 0
    dcs: DataCodingScheme = DataCodingScheme.GSM_7BIT
    validity_period: Optional[int] = None  # Relative VP (0-255)
    user_data: bytes = b""
    text: str = ""  # Decoded text (convenience)
    # Flags
    reject_duplicates: bool = False
    status_report_request: bool = False
    user_data_header: bool = False
    reply_path: bool = False

    @classmethod
    def from_bytes(cls, data: bytes) -> SMSSubmit:
        """Parse an SMS-SUBMIT TPDU from bytes."""
        msg = cls()
        offset = 0

        # Byte 0: flags
        flags = data[offset]
        offset += 1

        msg.reject_duplicates = bool(flags & 0x04)
        vpf = (flags >> 3) & 0x03
        msg.status_report_request = bool(flags & 0x20)
        msg.user_data_header = bool(flags & 0x40)
        msg.reply_path = bool(flags & 0x80)

        # TP-MR
        msg.message_ref = data[offset]
        offset += 1

        # TP-DA (Destination Address)
        msg.destination, offset = SMSAddress.from_bytes(data, offset)

        # TP-PID
        msg.protocol_id = data[offset]
        offset += 1

        # TP-DCS
        msg.dcs = DataCodingScheme(data[offset] & 0x0C)
        offset += 1

        # TP-VP (Validity Period, depends on VPF)
        if vpf == 0b10:  # Relative
            msg.validity_period = data[offset]
            offset += 1
        elif vpf == 0b11:  # Absolute (7 bytes)
            offset += 7
        elif vpf == 0b01:  # Enhanced (7 bytes)
            offset += 7

        # TP-UDL and TP-UD
        udl = data[offset]
        offset += 1

        if msg.dcs == DataCodingScheme.UCS2:
            # UDL is in octets
            msg.user_data = data[offset: offset + udl]
            msg.text = msg.user_data.decode("utf-16-be", errors="replace")
        elif msg.dcs == DataCodingScheme.GSM_7BIT:
            # UDL is in septets; packed bytes = ceil(udl * 7 / 8)
            packed_len = (udl * 7 + 7) // 8
            msg.user_data = data[offset: offset + packed_len]
            msg.text = decode_gsm7(msg.user_data, udl)
        else:
            # 8-bit data
            msg.user_data = data[offset: offset + udl]

        return msg

    def to_bytes(self) -> bytes:
        """Encode the SMS-SUBMIT TPDU to bytes."""
        result = bytearray()

        # Byte 0: flags
        flags = TPMessageType.SMS_SUBMIT
        if self.reject_duplicates:
            flags |= 0x04
        if self.validity_period is not None:
            flags |= 0x10  # VPF = relative
        if self.status_report_request:
            flags |= 0x20
        if self.user_data_header:
            flags |= 0x40
        if self.reply_path:
            flags |= 0x80
        result.append(flags)

        # TP-MR
        result.append(self.message_ref & 0xFF)

        # TP-DA
        result.extend(self.destination.to_bytes())

        # TP-PID
        result.append(self.protocol_id)

        # TP-DCS
        result.append(self.dcs)

        # TP-VP
        if self.validity_period is not None:
            result.append(self.validity_period)

        # Encode user data
        if self.text and not self.user_data:
            if self.dcs == DataCodingScheme.UCS2:
                self.user_data = self.text.encode("utf-16-be")
            elif self.dcs == DataCodingScheme.GSM_7BIT:
                self.user_data = encode_gsm7(self.text)

        # TP-UDL
        if self.dcs == DataCodingScheme.GSM_7BIT:
            udl = len(self.text) if self.text else (len(self.user_data) * 8) // 7
        elif self.dcs == DataCodingScheme.UCS2:
            udl = len(self.user_data)
        else:
            udl = len(self.user_data)

        result.append(udl)
        result.extend(self.user_data)

        return bytes(result)

    @classmethod
    def create(cls, dest_number: str, text: str,
               dcs: DataCodingScheme = DataCodingScheme.GSM_7BIT,
               msg_ref: int = 0) -> SMSSubmit:
        """Create an SMS-SUBMIT with text content."""
        msg = cls()
        msg.message_ref = msg_ref
        msg.destination = SMSAddress.international(dest_number)
        msg.dcs = dcs
        msg.text = text
        return msg


@dataclass
class SMSDeliver:
    """
    SMS-DELIVER TPDU (Mobile Terminated).

    Received by the UE from the network.
    """
    originator: SMSAddress = field(default_factory=SMSAddress)
    protocol_id: int = 0
    dcs: DataCodingScheme = DataCodingScheme.GSM_7BIT
    timestamp: bytes = b"\x00" * 7  # TP-SCTS (7 bytes BCD)
    user_data: bytes = b""
    text: str = ""
    # Flags
    more_messages: bool = True
    status_report_indication: bool = False
    user_data_header: bool = False
    reply_path: bool = False

    @classmethod
    def from_bytes(cls, data: bytes) -> SMSDeliver:
        """Parse an SMS-DELIVER TPDU from bytes."""
        msg = cls()
        offset = 0

        # Byte 0: flags
        flags = data[offset]
        offset += 1

        msg.more_messages = not bool(flags & 0x04)
        msg.status_report_indication = bool(flags & 0x20)
        msg.user_data_header = bool(flags & 0x40)
        msg.reply_path = bool(flags & 0x80)

        # TP-OA (Originating Address)
        msg.originator, offset = SMSAddress.from_bytes(data, offset)

        # TP-PID
        msg.protocol_id = data[offset]
        offset += 1

        # TP-DCS
        msg.dcs = DataCodingScheme(data[offset] & 0x0C)
        offset += 1

        # TP-SCTS (7 bytes BCD timestamp)
        msg.timestamp = data[offset: offset + 7]
        offset += 7

        # TP-UDL and TP-UD
        udl = data[offset]
        offset += 1

        if msg.dcs == DataCodingScheme.UCS2:
            msg.user_data = data[offset: offset + udl]
            msg.text = msg.user_data.decode("utf-16-be", errors="replace")
        elif msg.dcs == DataCodingScheme.GSM_7BIT:
            packed_len = (udl * 7 + 7) // 8
            msg.user_data = data[offset: offset + packed_len]
            msg.text = decode_gsm7(msg.user_data, udl)
        else:
            msg.user_data = data[offset: offset + udl]

        return msg

    def to_bytes(self) -> bytes:
        """Encode the SMS-DELIVER TPDU to bytes."""
        result = bytearray()

        # Byte 0: flags
        flags = TPMessageType.SMS_DELIVER
        if not self.more_messages:
            flags |= 0x04
        if self.status_report_indication:
            flags |= 0x20
        if self.user_data_header:
            flags |= 0x40
        if self.reply_path:
            flags |= 0x80
        result.append(flags)

        # TP-OA
        result.extend(self.originator.to_bytes())

        # TP-PID
        result.append(self.protocol_id)

        # TP-DCS
        result.append(self.dcs)

        # TP-SCTS
        result.extend(self.timestamp if len(self.timestamp) == 7 else b"\x00" * 7)

        # Encode user data
        if self.text and not self.user_data:
            if self.dcs == DataCodingScheme.UCS2:
                self.user_data = self.text.encode("utf-16-be")
            elif self.dcs == DataCodingScheme.GSM_7BIT:
                self.user_data = encode_gsm7(self.text)

        # TP-UDL
        if self.dcs == DataCodingScheme.GSM_7BIT:
            udl = len(self.text) if self.text else (len(self.user_data) * 8) // 7
        elif self.dcs == DataCodingScheme.UCS2:
            udl = len(self.user_data)
        else:
            udl = len(self.user_data)

        result.append(udl)
        result.extend(self.user_data)

        return bytes(result)

    @classmethod
    def create(cls, from_number: str, text: str,
               dcs: DataCodingScheme = DataCodingScheme.GSM_7BIT) -> SMSDeliver:
        """Create an SMS-DELIVER for incoming message delivery."""
        msg = cls()
        msg.originator = SMSAddress.international(from_number)
        msg.dcs = dcs
        msg.text = text
        msg.timestamp = encode_scts_now()
        return msg


class RPMessageType(IntEnum):
    """RP (Relay Protocol) message types per 3GPP TS 24.011."""
    RP_DATA_MO = 0x00   # MO: MS → network
    RP_DATA_MT = 0x01   # MT: network → MS
    RP_ACK_MO = 0x02
    RP_ACK_MT = 0x03
    RP_ERROR_MO = 0x04
    RP_ERROR_MT = 0x05


@dataclass
class RPData:
    """
    RP-DATA message per 3GPP TS 24.011.

    Wraps a TPDU for transport over SIP MESSAGE (SMS over IMS).
    Used as the body of SIP MESSAGE with Content-Type: application/vnd.3gpp.sms
    """
    msg_type: RPMessageType = RPMessageType.RP_DATA_MO
    reference: int = 0
    originator: bytes = b""  # RP-Originator Address (empty for MO)
    destination: bytes = b""  # RP-Destination Address (SMSC for MO, empty for MT)
    tpdu: bytes = b""

    @classmethod
    def wrap_mo(cls, tpdu: bytes, reference: int = 0,
                smsc: str = "") -> RPData:
        """Wrap a MO TPDU (SMS-SUBMIT) in RP-DATA for sending."""
        dest = b""
        if smsc:
            smsc_digits = smsc.replace("+", "")
            smsc_bcd = encode_bcd(smsc_digits)
            dest = bytes([len(smsc_bcd) + 1, 0x91]) + smsc_bcd  # International type
        return cls(
            msg_type=RPMessageType.RP_DATA_MO,
            reference=reference,
            originator=b"",
            destination=dest,
            tpdu=tpdu,
        )

    @classmethod
    def wrap_mt(cls, tpdu: bytes, reference: int = 0,
                smsc: str = "") -> RPData:
        """Wrap a MT TPDU (SMS-DELIVER) in RP-DATA for delivery."""
        orig = b""
        if smsc:
            smsc_digits = smsc.replace("+", "")
            smsc_bcd = encode_bcd(smsc_digits)
            orig = bytes([len(smsc_bcd) + 1, 0x91]) + smsc_bcd
        return cls(
            msg_type=RPMessageType.RP_DATA_MT,
            reference=reference,
            originator=orig,
            destination=b"",
            tpdu=tpdu,
        )

    def to_bytes(self) -> bytes:
        """Encode RP-DATA to bytes."""
        result = bytearray()
        result.append(self.msg_type)
        result.append(self.reference & 0xFF)

        # RP-Originator Address
        if self.originator:
            result.append(len(self.originator))
            result.extend(self.originator)
        else:
            result.append(0)

        # RP-Destination Address
        if self.destination:
            result.append(len(self.destination))
            result.extend(self.destination)
        else:
            result.append(0)

        # RP-User-Data (TPDU)
        result.append(len(self.tpdu))
        result.extend(self.tpdu)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> RPData:
        """Parse RP-DATA from bytes."""
        offset = 0
        msg_type = RPMessageType(data[offset])
        offset += 1

        reference = data[offset]
        offset += 1

        # RP-Originator Address
        orig_len = data[offset]
        offset += 1
        originator = data[offset: offset + orig_len] if orig_len > 0 else b""
        offset += orig_len

        # RP-Destination Address
        dest_len = data[offset]
        offset += 1
        destination = data[offset: offset + dest_len] if dest_len > 0 else b""
        offset += dest_len

        # RP-User-Data (TPDU)
        tpdu_len = data[offset]
        offset += 1
        tpdu = data[offset: offset + tpdu_len]

        return cls(
            msg_type=msg_type,
            reference=reference,
            originator=originator,
            destination=destination,
            tpdu=tpdu,
        )


@dataclass
class RPAck:
    """RP-ACK message per 3GPP TS 24.011."""
    msg_type: RPMessageType = RPMessageType.RP_ACK_MT
    reference: int = 0

    def to_bytes(self) -> bytes:
        return bytes([self.msg_type, self.reference & 0xFF])


# ---- GSM 7-bit encoding/decoding -------------------------------------------


def encode_gsm7(text: str) -> bytes:
    """Encode text using GSM 7-bit packed encoding."""
    septets = []
    for ch in text:
        code = GSM7_ENCODE.get(ch)
        if code is not None:
            septets.append(code)
        else:
            # Use '?' for unmappable characters
            septets.append(GSM7_ENCODE.get("?", 0x3F))

    # Pack septets into octets
    result = bytearray()
    shift = 0
    for i, septet in enumerate(septets):
        if shift == 7:
            shift = 0
            continue

        current = (septet >> shift) & 0xFF
        if i + 1 < len(septets):
            current |= (septets[i + 1] << (7 - shift)) & 0xFF
        result.append(current)
        shift += 1

    return bytes(result)


def decode_gsm7(data: bytes, num_septets: int) -> str:
    """Decode GSM 7-bit packed data to text."""
    septets = []
    shift = 0
    byte_idx = 0

    for _ in range(num_septets):
        if byte_idx >= len(data):
            break
        septet = (data[byte_idx] >> shift) & 0x7F
        if shift >= 1 and byte_idx + 1 < len(data):
            septet |= (data[byte_idx + 1] << (8 - shift)) & 0x7F
        elif shift >= 1 and byte_idx + 1 >= len(data):
            septet = (data[byte_idx] >> shift) & 0x7F

        septets.append(septet)
        shift += 1
        if shift == 7:
            shift = 0
            byte_idx += 1
        byte_idx += 1 if shift != 0 or _ == 0 else 0

    # Simpler approach: unpack all bits then extract septets
    bits = 0
    bit_count = 0
    for b in data:
        bits |= b << bit_count
        bit_count += 8

    text = []
    for i in range(num_septets):
        septet = (bits >> (i * 7)) & 0x7F
        if septet < len(GSM7_BASIC):
            text.append(GSM7_BASIC[septet])
        else:
            text.append("?")

    return "".join(text)


# ---- BCD encoding/decoding -------------------------------------------------


def encode_bcd(digits: str) -> bytes:
    """Encode a digit string to BCD (swapped nibble) format."""
    result = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i + 1]) if i + 1 < len(digits) else 0x0F
        result.append((high << 4) | low)
    return bytes(result)


def decode_bcd(data: bytes, num_digits: int) -> str:
    """Decode BCD (swapped nibble) data to a digit string."""
    digits = []
    for byte in data:
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low <= 9:
            digits.append(str(low))
        if high <= 9 and len(digits) < num_digits:
            digits.append(str(high))
    return "".join(digits[:num_digits])


# ---- Timestamp encoding ----------------------------------------------------


def encode_scts_now() -> bytes:
    """Encode current time as TP-SCTS (7 bytes BCD)."""
    t = time.gmtime()
    parts = [
        t.tm_year % 100,
        t.tm_mon,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
        0,  # Timezone (0 = UTC)
    ]
    return bytes(
        ((p % 10) << 4) | (p // 10) for p in parts
    )


def decode_scts(data: bytes) -> str:
    """Decode TP-SCTS to an ISO 8601-ish string."""
    if len(data) < 7:
        return ""
    parts = []
    for b in data[:7]:
        val = (b & 0x0F) * 10 + ((b >> 4) & 0x0F)
        parts.append(val)
    year = 2000 + parts[0]
    return f"{year:04d}-{parts[1]:02d}-{parts[2]:02d}T{parts[3]:02d}:{parts[4]:02d}:{parts[5]:02d}Z"


# ---- PDU parsing helpers (Android RIL format) -------------------------------


def parse_pdu_from_ril(hex_pdu: str) -> tuple[bytes, bytes]:
    """
    Parse a PDU string from Android RIL into (SMSC, TPDU).

    Android SEND_SMS PDU format:
    - First byte: SMSC length (0 = no SMSC)
    - SMSC address bytes (if length > 0)
    - Rest: TPDU
    """
    raw = bytes.fromhex(hex_pdu)
    smsc_len = raw[0]
    smsc = raw[1: 1 + smsc_len] if smsc_len > 0 else b""
    tpdu = raw[1 + smsc_len:]
    return smsc, tpdu


def build_pdu_for_ril(tpdu: bytes, smsc: bytes = b"") -> str:
    """
    Build a PDU hex string for Android RIL (NEW_SMS unsolicited).

    Format: SMSC_length + SMSC + TPDU
    """
    if smsc:
        return (bytes([len(smsc)]) + smsc + tpdu).hex().upper()
    else:
        return (bytes([0]) + tpdu).hex().upper()
