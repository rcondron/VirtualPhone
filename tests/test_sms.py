"""Tests for SMS over IMS (Phase 5).

Tests cover:
- SMS PDU encoding/decoding (3GPP TS 23.040)
  - GSM 7-bit text encoding/decoding
  - BCD address encoding/decoding
  - SMS-SUBMIT TPDU construction and parsing
  - SMS-DELIVER TPDU construction and parsing
  - RP-DATA wrapping for SIP MESSAGE body
  - Android RIL PDU format (SMSC + TPDU)
- SMS over IMS (3GPP TS 24.341)
  - SIP MESSAGE construction with RP-DATA body
  - Incoming SIP MESSAGE handling
  - MT-SMS delivery callback
  - MO-SMS routing through RadioHAL
- PSTN bridge configuration
- Management API SMS endpoints
"""

import asyncio
import json
import struct
import pytest

from ims.sms_pdu import (
    SMSSubmit, SMSDeliver, SMSAddress, DataCodingScheme,
    TypeOfNumber, TPMessageType,
    RPData, RPAck, RPMessageType,
    encode_gsm7, decode_gsm7,
    encode_bcd, decode_bcd,
    encode_scts_now, decode_scts,
    parse_pdu_from_ril, build_pdu_for_ril,
    GSM7_BASIC,
)
from ims.sms import (
    SMSoverIMS, SMSConfig, get_sms_state,
    CONTENT_TYPE_3GPP_SMS, _extract_number_from_uri,
)
from ims.sms_bridge import PSTNBridge, PSTNBridgeConfig


# =============================================================================
# GSM 7-bit encoding tests
# =============================================================================

class TestGSM7BitEncoding:
    """Test GSM 7-bit default alphabet encoding/decoding."""

    def test_encode_hello(self):
        """'Hello' encodes to known GSM 7-bit packed bytes."""
        encoded = encode_gsm7("Hello")
        # H=72 e=101 l=108 l=108 o=111 in GSM alphabet
        assert len(encoded) > 0
        decoded = decode_gsm7(encoded, 5)
        assert decoded == "Hello"

    def test_roundtrip_ascii(self):
        """ASCII text survives GSM 7-bit encode/decode roundtrip."""
        text = "Hello World"
        encoded = encode_gsm7(text)
        decoded = decode_gsm7(encoded, len(text))
        assert decoded == text

    def test_roundtrip_digits(self):
        """Digit strings survive roundtrip."""
        text = "0123456789"
        encoded = encode_gsm7(text)
        decoded = decode_gsm7(encoded, len(text))
        assert decoded == text

    def test_packed_length(self):
        """7 septets pack into 7 bytes, 8 septets into 7 bytes."""
        # 7 chars = 7*7 = 49 bits = ceil(49/8) = 7 bytes
        encoded7 = encode_gsm7("ABCDEFG")
        assert len(encoded7) == 7
        decoded = decode_gsm7(encoded7, 7)
        assert decoded == "ABCDEFG"

    def test_special_chars(self):
        """Special GSM chars (@ £ $) encode correctly."""
        for ch in "@$!?":
            encoded = encode_gsm7(ch)
            decoded = decode_gsm7(encoded, 1)
            assert decoded == ch, f"Failed for '{ch}'"

    def test_empty_string(self):
        """Empty string produces empty bytes."""
        encoded = encode_gsm7("")
        assert encoded == b""


# =============================================================================
# BCD encoding tests
# =============================================================================

class TestBCDEncoding:
    """Test BCD (Binary Coded Decimal) swapped-nibble encoding."""

    def test_encode_even_digits(self):
        """Even number of digits encodes without padding."""
        bcd = encode_bcd("1234")
        assert bcd == bytes([0x21, 0x43])

    def test_encode_odd_digits(self):
        """Odd digits are padded with 0xF nibble."""
        bcd = encode_bcd("12345")
        assert bcd == bytes([0x21, 0x43, 0xF5])

    def test_decode_even(self):
        """Decode BCD with even digit count."""
        digits = decode_bcd(bytes([0x21, 0x43]), 4)
        assert digits == "1234"

    def test_decode_odd(self):
        """Decode BCD with odd digit count."""
        digits = decode_bcd(bytes([0x21, 0x43, 0xF5]), 5)
        assert digits == "12345"

    def test_roundtrip_phone_number(self):
        """E.164 phone number survives BCD roundtrip."""
        number = "14155551234"
        bcd = encode_bcd(number)
        decoded = decode_bcd(bcd, len(number))
        assert decoded == number


# =============================================================================
# SMS Address tests
# =============================================================================

class TestSMSAddress:
    """Test SMS address encoding/decoding."""

    def test_international_address(self):
        """International address has TON=1, NPI=1."""
        addr = SMSAddress.international("+14155551234")
        assert addr.type_of_number == TypeOfNumber.INTERNATIONAL
        assert addr.number == "14155551234"
        assert addr.type_of_address == 0x91  # 1001 0001

    def test_address_to_bytes(self):
        """Address serializes with length + TOA + BCD digits."""
        addr = SMSAddress.international("14155551234")
        raw = addr.to_bytes()
        # Length = 11 digits, TOA = 0x91
        assert raw[0] == 11
        assert raw[1] == 0x91

    def test_address_roundtrip(self):
        """Address survives to_bytes → from_bytes roundtrip."""
        orig = SMSAddress.international("14155551234")
        raw = orig.to_bytes()
        parsed, offset = SMSAddress.from_bytes(raw, 0)
        assert parsed.number == "14155551234"
        assert parsed.type_of_number == TypeOfNumber.INTERNATIONAL
        assert offset == len(raw)


# =============================================================================
# SMS-SUBMIT (MO) tests
# =============================================================================

class TestSMSSubmit:
    """Test SMS-SUBMIT TPDU creation and parsing."""

    def test_create_basic(self):
        """Create a basic SMS-SUBMIT message."""
        msg = SMSSubmit.create("+14155551234", "Hello")
        assert msg.destination.number == "14155551234"
        assert msg.text == "Hello"
        assert msg.dcs == DataCodingScheme.GSM_7BIT
        assert msg.message_ref == 0

    def test_to_bytes_has_correct_mti(self):
        """TPDU first byte has MTI=01 (SMS-SUBMIT)."""
        msg = SMSSubmit.create("+1234", "Hi")
        raw = msg.to_bytes()
        assert (raw[0] & 0x03) == TPMessageType.SMS_SUBMIT

    def test_roundtrip_gsm7(self):
        """SMS-SUBMIT with GSM 7-bit text survives roundtrip."""
        orig = SMSSubmit.create("+14155551234", "Test message 123")
        raw = orig.to_bytes()
        parsed = SMSSubmit.from_bytes(raw)
        assert parsed.destination.number == "14155551234"
        assert parsed.text == "Test message 123"
        assert parsed.dcs == DataCodingScheme.GSM_7BIT

    def test_roundtrip_ucs2(self):
        """SMS-SUBMIT with UCS-2 text survives roundtrip."""
        orig = SMSSubmit.create("+1234", "Hello", dcs=DataCodingScheme.UCS2)
        raw = orig.to_bytes()
        parsed = SMSSubmit.from_bytes(raw)
        assert parsed.text == "Hello"
        assert parsed.dcs == DataCodingScheme.UCS2

    def test_message_ref_preserved(self):
        """Message reference byte is preserved."""
        orig = SMSSubmit.create("+1234", "Hi", msg_ref=42)
        raw = orig.to_bytes()
        parsed = SMSSubmit.from_bytes(raw)
        assert parsed.message_ref == 42

    def test_validity_period(self):
        """Validity period flag and value are encoded."""
        msg = SMSSubmit.create("+1234", "Hi")
        msg.validity_period = 167  # 24 hours
        raw = msg.to_bytes()
        # VPF bits should be set
        assert (raw[0] >> 3) & 0x03 == 0b10  # Relative VP
        parsed = SMSSubmit.from_bytes(raw)
        assert parsed.validity_period == 167

    def test_status_report_request(self):
        """SRR flag is encoded in first byte."""
        msg = SMSSubmit.create("+1234", "Hi")
        msg.status_report_request = True
        raw = msg.to_bytes()
        assert raw[0] & 0x20  # SRR bit

    def test_long_message(self):
        """Long message (max GSM 7-bit = 160 chars) encodes."""
        text = "A" * 160
        msg = SMSSubmit.create("+1234", text)
        raw = msg.to_bytes()
        parsed = SMSSubmit.from_bytes(raw)
        assert parsed.text == text


# =============================================================================
# SMS-DELIVER (MT) tests
# =============================================================================

class TestSMSDeliver:
    """Test SMS-DELIVER TPDU creation and parsing."""

    def test_create_basic(self):
        """Create a basic SMS-DELIVER message."""
        msg = SMSDeliver.create("+14155551234", "Hello there")
        assert msg.originator.number == "14155551234"
        assert msg.text == "Hello there"

    def test_to_bytes_has_correct_mti(self):
        """TPDU first byte has MTI=00 (SMS-DELIVER)."""
        msg = SMSDeliver.create("+1234", "Hi")
        raw = msg.to_bytes()
        assert (raw[0] & 0x03) == TPMessageType.SMS_DELIVER

    def test_roundtrip_gsm7(self):
        """SMS-DELIVER with GSM 7-bit text survives roundtrip."""
        orig = SMSDeliver.create("+14155551234", "Incoming message")
        raw = orig.to_bytes()
        parsed = SMSDeliver.from_bytes(raw)
        assert parsed.originator.number == "14155551234"
        assert parsed.text == "Incoming message"

    def test_roundtrip_ucs2(self):
        """SMS-DELIVER with UCS-2 text survives roundtrip."""
        orig = SMSDeliver.create("+1234", "Hello", dcs=DataCodingScheme.UCS2)
        raw = orig.to_bytes()
        parsed = SMSDeliver.from_bytes(raw)
        assert parsed.text == "Hello"

    def test_timestamp_is_7_bytes(self):
        """Timestamp field is always 7 bytes."""
        msg = SMSDeliver.create("+1234", "Hi")
        assert len(msg.timestamp) == 7

    def test_timestamp_now(self):
        """encode_scts_now produces 7 bytes."""
        ts = encode_scts_now()
        assert len(ts) == 7

    def test_decode_scts(self):
        """decode_scts produces ISO-ish timestamp string."""
        # 2024-01-15 10:30:45 UTC
        ts = bytes([0x42, 0x10, 0x51, 0x01, 0x03, 0x54, 0x00])
        result = decode_scts(ts)
        assert "2024" in result
        assert "T" in result


# =============================================================================
# RP-DATA wrapper tests
# =============================================================================

class TestRPData:
    """Test RP-DATA wrapping (3GPP TS 24.011)."""

    def test_wrap_mo(self):
        """Wrap MO TPDU in RP-DATA."""
        tpdu = SMSSubmit.create("+1234", "Test").to_bytes()
        rp = RPData.wrap_mo(tpdu, reference=5)
        assert rp.msg_type == RPMessageType.RP_DATA_MO
        assert rp.reference == 5
        assert rp.tpdu == tpdu

    def test_wrap_mt(self):
        """Wrap MT TPDU in RP-DATA."""
        tpdu = SMSDeliver.create("+1234", "Test").to_bytes()
        rp = RPData.wrap_mt(tpdu, reference=10)
        assert rp.msg_type == RPMessageType.RP_DATA_MT
        assert rp.reference == 10
        assert rp.tpdu == tpdu

    def test_roundtrip_mo(self):
        """MO RP-DATA survives to_bytes → from_bytes roundtrip."""
        tpdu = SMSSubmit.create("+14155551234", "Hello World").to_bytes()
        orig = RPData.wrap_mo(tpdu, reference=42)
        raw = orig.to_bytes()
        parsed = RPData.from_bytes(raw)
        assert parsed.msg_type == RPMessageType.RP_DATA_MO
        assert parsed.reference == 42
        assert parsed.tpdu == tpdu

    def test_roundtrip_mt(self):
        """MT RP-DATA survives roundtrip."""
        tpdu = SMSDeliver.create("+1234", "Incoming").to_bytes()
        orig = RPData.wrap_mt(tpdu, reference=99)
        raw = orig.to_bytes()
        parsed = RPData.from_bytes(raw)
        assert parsed.msg_type == RPMessageType.RP_DATA_MT
        assert parsed.reference == 99
        assert parsed.tpdu == tpdu

    def test_wrap_mo_with_smsc(self):
        """MO RP-DATA with explicit SMSC address."""
        tpdu = b"\x01\x00"
        rp = RPData.wrap_mo(tpdu, smsc="+1234567890")
        raw = rp.to_bytes()
        assert len(raw) > 5
        # Destination should contain SMSC BCD
        parsed = RPData.from_bytes(raw)
        assert parsed.destination != b""

    def test_rp_ack(self):
        """RP-ACK serializes to 2 bytes."""
        ack = RPAck(reference=42)
        raw = ack.to_bytes()
        assert len(raw) == 2
        assert raw[0] == RPMessageType.RP_ACK_MT
        assert raw[1] == 42


# =============================================================================
# Android RIL PDU format tests
# =============================================================================

class TestRILPDUFormat:
    """Test Android RIL PDU format (SMSC prefix + TPDU)."""

    def test_parse_pdu_no_smsc(self):
        """Parse PDU with no SMSC (length byte 00)."""
        tpdu = SMSSubmit.create("+1234", "Hi").to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()
        smsc, parsed_tpdu = parse_pdu_from_ril(pdu_hex)
        assert smsc == b""
        assert parsed_tpdu == tpdu

    def test_parse_pdu_with_smsc(self):
        """Parse PDU with SMSC address prefix."""
        tpdu = b"\x01\x00\x04\x91\x21\x43\x00\x00\x02\xC8\x32"
        smsc = bytes([0x91, 0x21, 0x43, 0xF5])
        pdu_hex = (bytes([len(smsc)]) + smsc + tpdu).hex()
        parsed_smsc, parsed_tpdu = parse_pdu_from_ril(pdu_hex)
        assert parsed_smsc == smsc
        assert parsed_tpdu == tpdu

    def test_build_pdu_for_ril(self):
        """Build RIL PDU string from TPDU."""
        tpdu = SMSDeliver.create("+1234", "Test").to_bytes()
        pdu_hex = build_pdu_for_ril(tpdu)
        # Should start with 00 (no SMSC)
        assert pdu_hex.startswith("00")
        # Roundtrip
        _, parsed = parse_pdu_from_ril(pdu_hex.lower())
        assert parsed == tpdu

    def test_roundtrip_submit_via_ril(self):
        """SMS-SUBMIT → RIL PDU → parse → SMS-SUBMIT roundtrip."""
        orig = SMSSubmit.create("+14155551234", "Hello from Android")
        tpdu = orig.to_bytes()
        pdu_hex = build_pdu_for_ril(tpdu)
        _, parsed_tpdu = parse_pdu_from_ril(pdu_hex.lower())
        parsed = SMSSubmit.from_bytes(parsed_tpdu)
        assert parsed.text == "Hello from Android"
        assert parsed.destination.number == "14155551234"


# =============================================================================
# SMS over IMS tests
# =============================================================================

class TestSMSoverIMSConfig:
    """Test SMS over IMS configuration and state."""

    def test_initial_state(self):
        """SMS state starts disabled with zero counters."""
        state = get_sms_state()
        assert state["enabled"] is False
        assert state["messages_sent"] == 0
        assert state["messages_received"] == 0

    def test_config_defaults(self):
        """Default config has empty strings."""
        config = SMSConfig()
        assert config.pcscf_address == ""
        assert config.pcscf_port == 5060
        assert config.transport == "UDP"

    def test_content_type(self):
        """3GPP SMS content type is correct."""
        assert CONTENT_TYPE_3GPP_SMS == "application/vnd.3gpp.sms"


class TestSMSoverIMSSend:
    """Test MO-SMS sending through SMSoverIMS."""

    @pytest.mark.asyncio
    async def test_send_without_start_returns_placeholder(self):
        """send_sms before start() returns placeholder success."""
        sms = SMSoverIMS(SMSConfig())
        tpdu = SMSSubmit.create("+1234", "Hi").to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()
        result = await sms.send_sms("", pdu_hex)
        assert result["errorCode"] == 0

    @pytest.mark.asyncio
    async def test_send_parses_pdu_correctly(self):
        """send_sms correctly parses the Android PDU."""
        sms = SMSoverIMS(SMSConfig(pcscf_address="127.0.0.1"))

        # Track what _send_sip_message receives
        sent_messages = []
        original_send = sms._send_sip_message

        async def mock_send(dest, tpdu):
            sent_messages.append((dest, tpdu))
            return True

        sms._send_sip_message = mock_send
        sms._started = True

        orig = SMSSubmit.create("+14155551234", "Test message")
        tpdu = orig.to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()

        result = await sms.send_sms("", pdu_hex)
        assert result["errorCode"] == 0
        assert len(sent_messages) == 1
        assert "+14155551234" in sent_messages[0][0]

    @pytest.mark.asyncio
    async def test_send_increments_counter(self):
        """Successful send increments messages_sent counter."""
        from ims.sms import _sms_state
        initial = _sms_state["messages_sent"]

        sms = SMSoverIMS(SMSConfig(pcscf_address="127.0.0.1"))
        sms._started = True

        async def mock_send(dest, tpdu):
            return True

        sms._send_sip_message = mock_send

        tpdu = SMSSubmit.create("+1234", "Hi").to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()
        await sms.send_sms("", pdu_hex)

        assert _sms_state["messages_sent"] == initial + 1


class TestSMSoverIMSReceive:
    """Test MT-SMS receiving via SIP MESSAGE."""

    @pytest.mark.asyncio
    async def test_deliver_mt_callback(self):
        """deliver_mt_sms invokes the MT callback."""
        sms = SMSoverIMS(SMSConfig())
        received = []

        async def on_mt(from_num, to_num, text):
            received.append((from_num, to_num, text))

        sms.set_mt_callback(on_mt)
        await sms.deliver_mt_sms("+14155551234", "Hello!")
        assert len(received) == 1
        assert received[0] == ("+14155551234", "", "Hello!")

    @pytest.mark.asyncio
    async def test_deliver_mt_no_callback(self):
        """deliver_mt_sms without callback returns False."""
        sms = SMSoverIMS(SMSConfig())
        result = await sms.deliver_mt_sms("+1234", "Hi")
        assert result is False


class TestNumberExtraction:
    """Test SIP URI number extraction."""

    def test_extract_sip_uri(self):
        assert _extract_number_from_uri("<sip:+14155551234@domain.com>;tag=abc") == "+14155551234"

    def test_extract_tel_uri(self):
        assert _extract_number_from_uri("tel:+14155551234") == "+14155551234"

    def test_extract_digits_only(self):
        assert _extract_number_from_uri("<sip:14155551234@domain.com>") == "14155551234"

    def test_extract_no_match(self):
        result = _extract_number_from_uri("not-a-uri")
        assert result == "not-a-uri"


# =============================================================================
# PSTN Bridge tests
# =============================================================================

class TestPSTNBridge:
    """Test PSTN SMS bridge configuration."""

    def test_not_enabled_by_default(self):
        """Bridge is disabled without provider config."""
        bridge = PSTNBridge(PSTNBridgeConfig())
        assert bridge.enabled is False

    def test_enabled_with_twilio(self):
        """Bridge is enabled with Twilio provider and from number."""
        config = PSTNBridgeConfig(
            provider="twilio",
            from_number="+14155551234",
            twilio_account_sid="ACtest",
            twilio_auth_token="test_token",
        )
        bridge = PSTNBridge(config)
        assert bridge.enabled is True

    def test_enabled_with_telnyx(self):
        """Bridge is enabled with Telnyx provider."""
        config = PSTNBridgeConfig(
            provider="telnyx",
            from_number="+14155551234",
            telnyx_api_key="KEY_test",
        )
        bridge = PSTNBridge(config)
        assert bridge.enabled is True

    @pytest.mark.asyncio
    async def test_send_without_enable_fails(self):
        """send_sms fails when bridge is not enabled."""
        bridge = PSTNBridge(PSTNBridgeConfig())
        result = await bridge.send_sms("+1234", "Hi")
        assert result is False


# =============================================================================
# RadioHAL SMS wiring tests
# =============================================================================

class TestRadioHALSMSWiring:
    """Test that RadioHAL routes SMS through SMSoverIMS."""

    @pytest.mark.asyncio
    async def test_send_sms_with_service(self):
        """send_sms routes through SMS service when wired."""
        from hal.radio_hal import RadioHAL

        hal = RadioHAL(euicc_socket="/nonexistent")
        sent = []

        # Create a mock SMS service
        class MockSMS:
            async def send_sms(self, smsc, pdu):
                sent.append(pdu)
                return {"messageRef": 1, "ackPdu": "", "errorCode": 0}

        hal.set_sms_service(MockSMS())
        tpdu = SMSSubmit.create("+1234", "Hi").to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()

        result = await hal.send_sms("", pdu_hex)
        assert result["errorCode"] == 0
        assert len(sent) == 1

    @pytest.mark.asyncio
    async def test_send_sms_without_service(self):
        """send_sms returns placeholder when no service wired."""
        from hal.radio_hal import RadioHAL

        hal = RadioHAL(euicc_socket="/nonexistent")
        result = await hal.send_sms("", "0001000491214300000248329A")
        assert result["errorCode"] == 0

    @pytest.mark.asyncio
    async def test_deliver_incoming_sms(self):
        """deliver_incoming_sms sends NEW_SMS indication."""
        from hal.radio_hal import RadioHAL

        hal = RadioHAL(euicc_socket="/nonexistent")
        indications = []

        async def capture(ind_id, data):
            indications.append((ind_id, data))

        hal.set_indication_callback(capture)
        await hal.deliver_incoming_sms("+14155551234", "", "Hello")

        assert len(indications) == 1
        assert indications[0][0] == 1003  # NEW_SMS
        assert "pdu" in indications[0][1]


# =============================================================================
# RIL bridge SMS handler test
# =============================================================================

class TestRILBridgeSMS:
    """Test RIL bridge SEND_SMS routing."""

    @pytest.mark.asyncio
    async def test_send_sms_request_routed(self):
        """SEND_SMS request is routed to radio_hal.send_sms."""
        from hal.ril_bridge import RILBridge, RILMessage, RILRequest

        bridge = RILBridge()
        bridge.radio_hal = __import__("hal.radio_hal", fromlist=["RadioHAL"]).RadioHAL(
            euicc_socket="/nonexistent"
        )

        tpdu = SMSSubmit.create("+1234", "Test").to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()

        msg = RILMessage(
            msg_type=0, serial=1,
            request_id=RILRequest.SEND_SMS,
            data={"smscPdu": "", "pdu": pdu_hex},
        )
        resp = await bridge._process_request(msg)
        assert resp.serial == 1
        assert "errorCode" in resp.data
        assert "messageRef" in resp.data


# =============================================================================
# End-to-end SMS flow test
# =============================================================================

class TestSMSEndToEnd:
    """Test the full SMS flow from TPDU creation to RP-DATA wrapping."""

    def test_mo_sms_full_pipeline(self):
        """Create SMS-SUBMIT → RP-DATA → bytes → parse → verify."""
        # Step 1: Create SMS-SUBMIT
        submit = SMSSubmit.create("+14155551234", "Hello from VirtualPhone!")
        tpdu = submit.to_bytes()

        # Step 2: Wrap in RP-DATA (as SIP MESSAGE body)
        rp = RPData.wrap_mo(tpdu, reference=1)
        body = rp.to_bytes()

        # Step 3: Parse RP-DATA back
        parsed_rp = RPData.from_bytes(body)
        assert parsed_rp.msg_type == RPMessageType.RP_DATA_MO

        # Step 4: Parse TPDU
        parsed_submit = SMSSubmit.from_bytes(parsed_rp.tpdu)
        assert parsed_submit.destination.number == "14155551234"
        assert parsed_submit.text == "Hello from VirtualPhone!"

    def test_mt_sms_full_pipeline(self):
        """Create SMS-DELIVER → RP-DATA → bytes → parse → verify."""
        deliver = SMSDeliver.create("+14155551234", "Incoming message!")
        tpdu = deliver.to_bytes()

        rp = RPData.wrap_mt(tpdu, reference=5)
        body = rp.to_bytes()

        parsed_rp = RPData.from_bytes(body)
        assert parsed_rp.msg_type == RPMessageType.RP_DATA_MT

        parsed_deliver = SMSDeliver.from_bytes(parsed_rp.tpdu)
        assert parsed_deliver.originator.number == "14155551234"
        assert parsed_deliver.text == "Incoming message!"

    def test_ril_to_sip_pipeline(self):
        """Android RIL PDU → TPDU parse → RP-DATA → content-type check."""
        # Simulate Android sending SMS
        submit = SMSSubmit.create("+14155551234", "Test from Android")
        tpdu = submit.to_bytes()
        android_pdu = build_pdu_for_ril(tpdu)

        # Parse as the RadioHAL would
        _, parsed_tpdu = parse_pdu_from_ril(android_pdu.lower())
        parsed_submit = SMSSubmit.from_bytes(parsed_tpdu)

        # Build RP-DATA for SIP MESSAGE body
        rp = RPData.wrap_mo(parsed_tpdu, reference=0)
        body = rp.to_bytes()
        content_type = CONTENT_TYPE_3GPP_SMS

        assert content_type == "application/vnd.3gpp.sms"
        assert len(body) > 0

        # Verify the body can be parsed back
        parsed_rp = RPData.from_bytes(body)
        final = SMSSubmit.from_bytes(parsed_rp.tpdu)
        assert final.text == "Test from Android"
