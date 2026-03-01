"""
APDU (Application Protocol Data Unit) command handler.

Processes ISO 7816-4 APDU commands as used by the eUICC / UICC interface.
This bridges between the Android telephony framework (via RIL) and the
virtual eUICC internals.

Reference: ISO/IEC 7816-4, ETSI TS 102.221, GSMA SGP.22
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from euicc.euicc import VirtualEUICC

logger = logging.getLogger(__name__)


# Status words (SW1 SW2)
SW_OK = (0x90, 0x00)
SW_NOT_FOUND = (0x6A, 0x82)
SW_WRONG_P1P2 = (0x6A, 0x86)
SW_WRONG_LENGTH = (0x67, 0x00)
SW_WRONG_DATA = (0x6A, 0x80)
SW_CONDITIONS_NOT_SATISFIED = (0x69, 0x85)
SW_SECURITY_NOT_SATISFIED = (0x69, 0x82)
SW_INS_NOT_SUPPORTED = (0x6D, 0x00)
SW_CLA_NOT_SUPPORTED = (0x6E, 0x00)
SW_INTERNAL_ERROR = (0x6F, 0x00)


class INS(IntEnum):
    """ISO 7816-4 instruction bytes relevant to UICC."""
    SELECT = 0xA4
    READ_BINARY = 0xB0
    READ_RECORD = 0xB2
    GET_RESPONSE = 0xC0
    UPDATE_BINARY = 0xD6
    UPDATE_RECORD = 0xDC
    STATUS = 0xF2
    VERIFY_PIN = 0x20
    MANAGE_CHANNEL = 0x70
    GET_DATA = 0xCA
    STORE_DATA = 0xE2
    # SGP.22 specific
    GET_EUICC_INFO = 0xBF
    AUTHENTICATE = 0x88


@dataclass
class APDUCommand:
    """A parsed APDU command."""
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = b""
    le: int = 0  # Expected response length

    @classmethod
    def from_bytes(cls, raw: bytes) -> APDUCommand:
        """Parse an APDU command from raw bytes."""
        if len(raw) < 4:
            raise ValueError("APDU too short")

        cla, ins, p1, p2 = raw[0], raw[1], raw[2], raw[3]
        data = b""
        le = 0

        if len(raw) == 4:
            # Case 1: No data, no Le
            pass
        elif len(raw) == 5:
            # Case 2: No data, Le present
            le = raw[4] or 256
        else:
            # Case 3/4: Data present
            lc = raw[4]
            data = raw[5:5 + lc]
            if len(raw) > 5 + lc:
                le = raw[5 + lc] or 256

        return cls(cla=cla, ins=ins, p1=p1, p2=p2, data=data, le=le)

    def to_bytes(self) -> bytes:
        """Serialize to raw bytes."""
        header = bytes([self.cla, self.ins, self.p1, self.p2])
        if self.data:
            return header + bytes([len(self.data)]) + self.data
        if self.le:
            return header + bytes([self.le & 0xFF])
        return header


@dataclass
class APDUResponse:
    """An APDU response."""
    data: bytes
    sw1: int
    sw2: int

    def to_bytes(self) -> bytes:
        return self.data + bytes([self.sw1, self.sw2])

    @property
    def is_success(self) -> bool:
        return self.sw1 == 0x90 and self.sw2 == 0x00

    @property
    def status_word(self) -> str:
        return f"{self.sw1:02X}{self.sw2:02X}"


# Elementary File IDs for USIM (ETSI TS 131.102)
EF_IMSI = 0x6F07
EF_ICCID = 0x2FE2
EF_SPN = 0x6F46
EF_MSISDN = 0x6F40
EF_HPLMN = 0x6F31
EF_AD = 0x6FAD
EF_UST = 0x6F38
EF_ACC = 0x6F78
EF_DOMAIN = 0x6F03  # ISIM
EF_IMPI = 0x6F02    # ISIM
EF_IMPU = 0x6F04    # ISIM


class APDUHandler:
    """
    Processes APDU commands directed at the virtual eUICC.

    Routes commands to the appropriate ISD-P / application based on
    the currently selected file/application.
    """

    def __init__(self, euicc: VirtualEUICC):
        self.euicc = euicc
        self._selected_ef: Optional[int] = None
        self._pending_response: Optional[bytes] = None

    def process(self, raw: bytes) -> APDUResponse:
        """Process a raw APDU command and return a response."""
        try:
            cmd = APDUCommand.from_bytes(raw)
        except ValueError as e:
            logger.error("Invalid APDU: %s", e)
            return APDUResponse(b"", *SW_WRONG_LENGTH)

        logger.debug(
            "APDU: CLA=%02X INS=%02X P1=%02X P2=%02X Lc=%d",
            cmd.cla, cmd.ins, cmd.p1, cmd.p2, len(cmd.data),
        )

        try:
            return self._dispatch(cmd)
        except Exception:
            logger.exception("APDU processing error")
            return APDUResponse(b"", *SW_INTERNAL_ERROR)

    def _dispatch(self, cmd: APDUCommand) -> APDUResponse:
        """Route an APDU command to the appropriate handler."""
        handlers = {
            INS.SELECT: self._handle_select,
            INS.READ_BINARY: self._handle_read_binary,
            INS.READ_RECORD: self._handle_read_record,
            INS.GET_RESPONSE: self._handle_get_response,
            INS.STATUS: self._handle_status,
            INS.AUTHENTICATE: self._handle_authenticate,
            INS.STORE_DATA: self._handle_store_data,
        }

        handler = handlers.get(cmd.ins)
        if handler is None:
            return APDUResponse(b"", *SW_INS_NOT_SUPPORTED)

        return handler(cmd)

    def _handle_select(self, cmd: APDUCommand) -> APDUResponse:
        """Handle SELECT command (INS=A4)."""
        if cmd.p1 == 0x04:
            # Select by AID (DF name)
            logger.debug("SELECT by AID: %s", cmd.data.hex())
            return APDUResponse(b"", *SW_OK)
        elif cmd.p1 == 0x00:
            # Select by file ID
            if len(cmd.data) >= 2:
                file_id = (cmd.data[0] << 8) | cmd.data[1]
                self._selected_ef = file_id
                logger.debug("SELECT EF: %04X", file_id)
                return APDUResponse(b"", *SW_OK)

        return APDUResponse(b"", *SW_WRONG_P1P2)

    def _handle_read_binary(self, cmd: APDUCommand) -> APDUResponse:
        """Handle READ BINARY (INS=B0) - read transparent EF data."""
        if self._selected_ef is None:
            return APDUResponse(b"", *SW_CONDITIONS_NOT_SATISFIED)

        profile = self.euicc.get_active_profile()
        if profile is None:
            return APDUResponse(b"", *SW_CONDITIONS_NOT_SATISFIED)

        data = self._read_ef(self._selected_ef, profile)
        if data is None:
            return APDUResponse(b"", *SW_NOT_FOUND)

        # Apply offset
        offset = (cmd.p1 << 8) | cmd.p2
        data = data[offset:]

        # Apply Le (length expected)
        if cmd.le > 0:
            data = data[:cmd.le]

        return APDUResponse(data, *SW_OK)

    def _handle_read_record(self, cmd: APDUCommand) -> APDUResponse:
        """Handle READ RECORD (INS=B2)."""
        if self._selected_ef is None:
            return APDUResponse(b"", *SW_CONDITIONS_NOT_SATISFIED)

        profile = self.euicc.get_active_profile()
        if profile is None:
            return APDUResponse(b"", *SW_CONDITIONS_NOT_SATISFIED)

        data = self._read_ef(self._selected_ef, profile)
        if data is None:
            return APDUResponse(b"", *SW_NOT_FOUND)

        return APDUResponse(data, *SW_OK)

    def _handle_get_response(self, cmd: APDUCommand) -> APDUResponse:
        """Handle GET RESPONSE (INS=C0) - retrieve pending data."""
        if self._pending_response is None:
            return APDUResponse(b"", *SW_CONDITIONS_NOT_SATISFIED)

        data = self._pending_response
        self._pending_response = None
        return APDUResponse(data, *SW_OK)

    def _handle_status(self, cmd: APDUCommand) -> APDUResponse:
        """Handle STATUS (INS=F2)."""
        info = self.euicc.get_euicc_info()
        data = str(info).encode()[:cmd.le or 256]
        return APDUResponse(data, *SW_OK)

    def _handle_authenticate(self, cmd: APDUCommand) -> APDUResponse:
        """
        Handle AUTHENTICATE (INS=88) - SIM/AKA authentication.

        This is the core command used by the network to authenticate
        the subscriber. It runs the Milenage algorithm.
        """
        from euicc.crypto.milenage import Milenage

        profile = self.euicc.get_active_profile()
        if profile is None:
            return APDUResponse(b"", *SW_CONDITIONS_NOT_SATISFIED)

        usim = profile.get_usim_data()

        # Parse AUTHENTICATE data: context type + RAND + AUTN
        if len(cmd.data) < 34:
            return APDUResponse(b"", *SW_WRONG_LENGTH)

        context = cmd.data[0]  # 0x80 = 3G context, 0x00 = 2G
        rand_len = cmd.data[1]
        rand_val = cmd.data[2:2 + rand_len]

        if context == 0x80 and len(cmd.data) >= 2 + rand_len + 2:
            # 3G/4G UMTS authentication (AKA)
            autn_offset = 2 + rand_len
            autn_len = cmd.data[autn_offset]
            autn = cmd.data[autn_offset + 1:autn_offset + 1 + autn_len]

            ki = bytes.fromhex(usim["ki"])
            opc = bytes.fromhex(usim["opc"])
            sqn = usim["sqn"]

            mil = Milenage(ki, opc)
            result = mil.authenticate(rand_val, autn, sqn)

            if result is None:
                # Sync failure - return AUTS
                auts = mil.generate_auts(rand_val, sqn)
                resp_data = bytes([0xDC, len(auts)]) + auts
                return APDUResponse(resp_data, *SW_OK)

            res, ck, ik = result
            profile.increment_sqn()

            # Build success response: DB + len(RES) + RES + len(CK) + CK + len(IK) + IK
            resp_data = (
                bytes([0xDB, len(res)]) + res +
                bytes([len(ck)]) + ck +
                bytes([len(ik)]) + ik
            )
            return APDUResponse(resp_data, *SW_OK)
        else:
            # 2G GSM authentication
            ki = bytes.fromhex(usim["ki"])
            opc = bytes.fromhex(usim["opc"])
            mil = Milenage(ki, opc)
            sres, kc = mil.gsm_authenticate(rand_val)

            resp_data = bytes([len(sres)]) + sres + bytes([len(kc)]) + kc
            return APDUResponse(resp_data, *SW_OK)

    def _handle_store_data(self, cmd: APDUCommand) -> APDUResponse:
        """Handle STORE DATA (INS=E2) - used during RSP profile download."""
        logger.info("STORE DATA: %d bytes", len(cmd.data))
        return APDUResponse(b"", *SW_OK)

    def _read_ef(self, file_id: int, profile) -> Optional[bytes]:
        """Read data from an Elementary File in the active profile."""
        ef_map = {
            EF_IMSI: self._encode_imsi(profile.imsi),
            EF_ICCID: self._encode_bcd(profile.iccid),
            EF_SPN: profile.spn.encode().ljust(16, b"\xff"),
            EF_MSISDN: self._encode_msisdn(profile.msisdn),
            EF_HPLMN: self._encode_plmn(profile.mcc, profile.mnc),
            EF_AD: bytes([0x00, 0x00, len(profile.mnc), 0x00]),
        }

        # ISIM elementary files
        isim = profile.get_isim_data()
        if isim:
            ef_map[EF_IMPI] = isim["impi"].encode()
            ef_map[EF_IMPU] = isim["impu"].encode()
            ef_map[EF_DOMAIN] = isim["home_domain"].encode()

        return ef_map.get(file_id)

    @staticmethod
    def _encode_imsi(imsi: str) -> bytes:
        """Encode IMSI in 3GPP BCD format (ETSI TS 131.102)."""
        length = (len(imsi) + 1) // 2 + 1
        result = bytes([length])

        # First byte: parity + first digit
        parity = len(imsi) & 1
        first = int(imsi[0]) if imsi else 0
        result += bytes([(0x09 if parity else 0x01) | (first << 4)])

        # Remaining digits in BCD pairs
        remaining = imsi[1:]
        for i in range(0, len(remaining), 2):
            d1 = int(remaining[i])
            d2 = int(remaining[i + 1]) if i + 1 < len(remaining) else 0xF
            result += bytes([d1 | (d2 << 4)])

        return result

    @staticmethod
    def _encode_bcd(digits: str) -> bytes:
        """Encode a digit string in BCD format."""
        result = b""
        for i in range(0, len(digits), 2):
            d1 = int(digits[i])
            d2 = int(digits[i + 1]) if i + 1 < len(digits) else 0xF
            result += bytes([d1 | (d2 << 4)])
        return result

    @staticmethod
    def _encode_plmn(mcc: str, mnc: str) -> bytes:
        """Encode PLMN ID (MCC+MNC) in 3GPP format (3GPP TS 24.008)."""
        def _nibble(ch: str) -> int:
            return 0xF if ch.upper() == "F" else int(ch)

        mcc = mcc.ljust(3, "F")
        mnc = mnc.ljust(3, "F")
        return bytes([
            (_nibble(mcc[1]) << 4) | _nibble(mcc[0]),
            (_nibble(mnc[2]) << 4) | _nibble(mcc[2]),
            (_nibble(mnc[1]) << 4) | _nibble(mnc[0]),
        ])

    @staticmethod
    def _encode_msisdn(msisdn: Optional[str]) -> bytes:
        """Encode MSISDN per ETSI TS 131.102."""
        if not msisdn:
            return b"\xff" * 14
        # Alpha tag (empty) + BCD number + capability
        number = msisdn.lstrip("+")
        ton_npi = 0x91 if msisdn.startswith("+") else 0x81  # International / unknown
        bcd = b""
        for i in range(0, len(number), 2):
            d1 = int(number[i])
            d2 = int(number[i + 1]) if i + 1 < len(number) else 0xF
            bcd += bytes([d1 | (d2 << 4)])
        bcd_len = len(bcd) + 1  # +1 for TON/NPI byte
        return bytes([bcd_len, ton_npi]) + bcd
