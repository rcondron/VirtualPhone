"""Tests for VoLTE voice calls (Phase 6).

Tests cover:
- VoLTE call state machine (VoLTECallState transitions)
- VoLTEConfig defaults and codec priority
- VoLTECallManager call lifecycle:
  - MO call initiation (SIP INVITE → 200 OK → ACK)
  - MT call reception (INVITE → 180 Ringing → answer → 200 OK)
  - Hangup via SIP BYE
  - Incoming BYE / CANCEL handling
- RadioHAL VoiceCall state management:
  - dial() creates DIALING call, triggers INVITE
  - answer() accepts INCOMING call
  - hangup() terminates call via BYE
  - incoming_call() creates INCOMING call, sends CALL_RING
  - update_call_state() transitions call states
  - get_current_calls() returns correct call list
- RIL bridge DIAL / HANGUP / ANSWER handlers
- SDP offer building and codec extraction
- Service-Route storage in IMSRegistration
- Management API VoLTE endpoints
- Module-level get_volte_state()
"""

import asyncio
import json
import struct
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ims.volte import (
    VoLTECallManager, VoLTEConfig, VoLTECallState, VoLTECall,
    VoLTESession,
    build_sdp_offer, get_volte_state,
    _extract_codec_from_sdp, _extract_number_from_uri,
)
from ims.sip_client import SIPMessage, SIPStatus, generate_call_id
from hal.radio_hal import RadioHAL, CallState, VoiceCall


# =============================================================================
# VoLTEConfig tests
# =============================================================================

class TestVoLTEConfig:
    """Test VoLTE configuration defaults."""

    def test_default_codec_priority(self):
        """Default codec priority should be AMR-WB, AMR-NB, EVS."""
        cfg = VoLTEConfig()
        assert cfg.codec_priority == ["AMR-WB", "AMR-NB", "EVS"]

    def test_custom_codec_priority(self):
        """Custom codec priority overrides default."""
        cfg = VoLTEConfig(codec_priority=["EVS", "AMR-WB"])
        assert cfg.codec_priority == ["EVS", "AMR-WB"]

    def test_default_qci(self):
        """QCI defaults to 1 (conversational voice)."""
        cfg = VoLTEConfig()
        assert cfg.qci == 1

    def test_default_rtp_port_base(self):
        cfg = VoLTEConfig()
        assert cfg.rtp_port_base == 50000

    def test_ipsec_transport_default(self):
        cfg = VoLTEConfig()
        assert cfg.use_ipsec_transport is True


# =============================================================================
# VoLTECallState tests
# =============================================================================

class TestVoLTECallState:
    """Test VoLTE call state enum."""

    def test_all_states_exist(self):
        assert VoLTECallState.INITIATING.value == "initiating"
        assert VoLTECallState.RINGING_OUT.value == "ringing_out"
        assert VoLTECallState.RINGING_IN.value == "ringing_in"
        assert VoLTECallState.ACTIVE.value == "active"
        assert VoLTECallState.HELD.value == "held"
        assert VoLTECallState.TERMINATING.value == "terminating"
        assert VoLTECallState.ENDED.value == "ended"


# =============================================================================
# VoLTECall dataclass tests
# =============================================================================

class TestVoLTECall:
    """Test VoLTE call dataclass."""

    def test_default_values(self):
        call = VoLTECall()
        assert call.sip_call_id == ""
        assert call.radio_call_index == 0
        assert call.state == VoLTECallState.INITIATING
        assert call.direction == "MO"
        assert call.remote_number == ""
        assert call.rtp_port == 0
        assert call.codec == ""

    def test_custom_values(self):
        call = VoLTECall(
            sip_call_id="abc@host",
            radio_call_index=2,
            state=VoLTECallState.ACTIVE,
            direction="MT",
            remote_number="+15551234567",
            rtp_port=50000,
            codec="AMR-WB",
        )
        assert call.sip_call_id == "abc@host"
        assert call.direction == "MT"
        assert call.codec == "AMR-WB"


# =============================================================================
# SDP building tests
# =============================================================================

class TestBuildSDPOffer:
    """Test SDP offer construction."""

    def test_sdp_contains_version(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "v=0\r\n" in sdp

    def test_sdp_contains_origin(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "o=VirtualPhone" in sdp
        assert "10.0.0.1" in sdp

    def test_sdp_contains_connection(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "c=IN IP4 10.0.0.1" in sdp

    def test_sdp_contains_media_line(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "m=audio 50000 RTP/AVP" in sdp

    def test_sdp_contains_amr_wb(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "AMR-WB/16000/1" in sdp

    def test_sdp_contains_amr_nb(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "AMR/8000/1" in sdp

    def test_sdp_contains_telephone_event(self):
        """telephone-event for DTMF should always be present."""
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "telephone-event/8000" in sdp

    def test_sdp_ptime(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "a=ptime:20" in sdp

    def test_sdp_sendrecv(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "a=sendrecv" in sdp

    def test_custom_codecs(self):
        sdp = build_sdp_offer("10.0.0.1", 50000, ["EVS"])
        assert "EVS/16000/1" in sdp
        # telephone-event still present
        assert "telephone-event" in sdp

    def test_custom_port(self):
        sdp = build_sdp_offer("10.0.0.1", 60000)
        assert "m=audio 60000 RTP/AVP" in sdp


# =============================================================================
# SDP codec extraction tests
# =============================================================================

class TestExtractCodecFromSDP:
    """Test codec extraction from SDP answers."""

    def test_extract_amr_wb(self):
        sdp = "v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n"
        assert _extract_codec_from_sdp(sdp) == "AMR-WB"

    def test_extract_amr_nb(self):
        sdp = "v=0\r\na=rtpmap:97 AMR/8000/1\r\n"
        assert _extract_codec_from_sdp(sdp) == "AMR"

    def test_extract_evs(self):
        sdp = "v=0\r\na=rtpmap:98 EVS/16000/1\r\n"
        assert _extract_codec_from_sdp(sdp) == "EVS"

    def test_no_codec(self):
        sdp = "v=0\r\nm=audio 50000 RTP/AVP 0\r\n"
        assert _extract_codec_from_sdp(sdp) == "unknown"


# =============================================================================
# Number extraction from SIP URI tests
# =============================================================================

class TestExtractNumberFromURI:
    """Test phone number extraction from SIP/tel URIs."""

    def test_sip_uri(self):
        assert _extract_number_from_uri("sip:15551234567@ims.example.com") == "15551234567"

    def test_sip_uri_with_plus(self):
        assert _extract_number_from_uri("sip:+15551234567@ims.example.com") == "+15551234567"

    def test_tel_uri(self):
        assert _extract_number_from_uri("tel:+15551234567") == "+15551234567"

    def test_display_name_sip(self):
        uri = '"John" <sip:15551234567@ims.example.com>;tag=abc'
        assert _extract_number_from_uri(uri) == "15551234567"

    def test_no_match(self):
        assert _extract_number_from_uri("unknown") == "unknown"


# =============================================================================
# RadioHAL VoiceCall tests
# =============================================================================

class TestVoiceCallDataclass:
    """Test VoiceCall dataclass and to_ril_dict serialization."""

    def test_defaults(self):
        vc = VoiceCall()
        assert vc.index == 1
        assert vc.state == CallState.DIALING
        assert vc.is_mt is False
        assert vc.number == ""

    def test_to_ril_dict(self):
        vc = VoiceCall(
            index=2,
            state=CallState.ACTIVE,
            is_mt=True,
            number="+15551234567",
        )
        d = vc.to_ril_dict()
        assert d["state"] == CallState.ACTIVE.value
        assert d["index"] == 2
        assert d["isMT"] is True
        assert d["number"] == "+15551234567"

    def test_call_states_match_android(self):
        """Call states should match Android DriverCall.State values."""
        assert CallState.ACTIVE == 0
        assert CallState.HOLDING == 1
        assert CallState.DIALING == 2
        assert CallState.ALERTING == 3
        assert CallState.INCOMING == 4
        assert CallState.WAITING == 5


# =============================================================================
# RadioHAL dial/answer/hangup tests
# =============================================================================

class TestRadioHALCallManagement:
    """Test RadioHAL voice call management methods."""

    def _make_hal(self):
        hal = RadioHAL.__new__(RadioHAL)
        hal.voice_calls = []
        hal._next_call_index = 1
        hal._call_manager = None
        hal._indication_callback = AsyncMock()
        hal._sms_service = None
        hal.euicc_socket = "/run/vphone/euicc.sock"
        hal.radio_state = 10
        hal.sim_status = MagicMock()
        hal.registration = MagicMock()
        hal.data_calls = []
        hal.imei = "123456789012345"
        hal._registration_task = None
        hal._cf_manager = None
        hal._ussd_handler = None
        hal._muted = False
        return hal

    @pytest.mark.asyncio
    async def test_dial_creates_call(self):
        """dial() should create a DIALING VoiceCall."""
        hal = self._make_hal()
        result = await hal.dial("+15551234567")
        assert result["success"] is True
        assert len(hal.voice_calls) == 1
        assert hal.voice_calls[0].state == CallState.DIALING
        assert hal.voice_calls[0].number == "+15551234567"
        assert hal.voice_calls[0].is_mt is False

    @pytest.mark.asyncio
    async def test_dial_sends_indication(self):
        """dial() should send CALL_STATE_CHANGED indication."""
        hal = self._make_hal()
        await hal.dial("+15551234567")
        # At least one indication call (CALL_STATE_CHANGED)
        assert hal._indication_callback.call_count >= 1

    @pytest.mark.asyncio
    async def test_dial_with_call_manager(self):
        """dial() with a call manager should call initiate_call()."""
        hal = self._make_hal()
        mgr = AsyncMock()
        mgr.initiate_call = AsyncMock(return_value="sip-call-123@vp")
        hal._call_manager = mgr

        result = await hal.dial("+15551234567")
        assert result["success"] is True
        mgr.initiate_call.assert_awaited_once()
        assert hal.voice_calls[0].sip_call_id == "sip-call-123@vp"

    @pytest.mark.asyncio
    async def test_dial_invite_failure(self):
        """dial() should clean up if INVITE fails."""
        hal = self._make_hal()
        mgr = AsyncMock()
        mgr.initiate_call = AsyncMock(return_value=None)
        hal._call_manager = mgr

        result = await hal.dial("+15551234567")
        assert result["success"] is False
        assert len(hal.voice_calls) == 0

    @pytest.mark.asyncio
    async def test_incoming_call(self):
        """incoming_call() should create INCOMING VoiceCall and send indications."""
        hal = self._make_hal()
        await hal.incoming_call("+15559876543", "call-id-abc")

        assert len(hal.voice_calls) == 1
        assert hal.voice_calls[0].state == CallState.INCOMING
        assert hal.voice_calls[0].is_mt is True
        assert hal.voice_calls[0].number == "+15559876543"
        assert hal.voice_calls[0].sip_call_id == "call-id-abc"

        # Should send CALL_RING and CALL_STATE_CHANGED
        assert hal._indication_callback.call_count >= 2

    @pytest.mark.asyncio
    async def test_answer_incoming_call(self):
        """answer() should transition INCOMING call to ACTIVE."""
        hal = self._make_hal()
        await hal.incoming_call("+15559876543", "call-id-abc")

        result = await hal.answer()
        assert result["success"] is True
        assert hal.voice_calls[0].state == CallState.ACTIVE

    @pytest.mark.asyncio
    async def test_answer_with_call_manager(self):
        """answer() with call manager should call answer_call()."""
        hal = self._make_hal()
        mgr = AsyncMock()
        mgr.answer_call = AsyncMock(return_value=True)
        hal._call_manager = mgr

        await hal.incoming_call("+15559876543", "call-id-abc")
        await hal.answer()

        mgr.answer_call.assert_awaited_once_with("call-id-abc")

    @pytest.mark.asyncio
    async def test_answer_no_incoming(self):
        """answer() should fail if no incoming call."""
        hal = self._make_hal()
        result = await hal.answer()
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_hangup_removes_call(self):
        """hangup() should remove the call."""
        hal = self._make_hal()
        await hal.dial("+15551234567")
        call_index = hal.voice_calls[0].index

        result = await hal.hangup(call_index)
        assert result["success"] is True
        assert len(hal.voice_calls) == 0

    @pytest.mark.asyncio
    async def test_hangup_with_call_manager(self):
        """hangup() with call manager should call hangup_call()."""
        hal = self._make_hal()
        mgr = AsyncMock()
        mgr.initiate_call = AsyncMock(return_value="sip-123")
        mgr.hangup_call = AsyncMock(return_value=True)
        hal._call_manager = mgr

        await hal.dial("+15551234567")
        call_index = hal.voice_calls[0].index
        await hal.hangup(call_index)

        mgr.hangup_call.assert_awaited_once_with("sip-123")

    @pytest.mark.asyncio
    async def test_hangup_nonexistent(self):
        """hangup() should fail for nonexistent call index."""
        hal = self._make_hal()
        result = await hal.hangup(99)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_hangup_all(self):
        """hangup_all() should clear all calls."""
        hal = self._make_hal()
        await hal.dial("+15551111111")
        await hal.dial("+15552222222")
        assert len(hal.voice_calls) == 2

        result = await hal.hangup_all()
        assert result["success"] is True
        assert len(hal.voice_calls) == 0

    @pytest.mark.asyncio
    async def test_update_call_state(self):
        """update_call_state() should transition call state."""
        hal = self._make_hal()
        await hal.dial("+15551234567")
        call_index = hal.voice_calls[0].index

        await hal.update_call_state(call_index, CallState.ALERTING)
        assert hal.voice_calls[0].state == CallState.ALERTING

        await hal.update_call_state(call_index, CallState.ACTIVE)
        assert hal.voice_calls[0].state == CallState.ACTIVE

    @pytest.mark.asyncio
    async def test_get_current_calls_empty(self):
        """get_current_calls() should return empty list when no calls."""
        hal = self._make_hal()
        result = await hal.get_current_calls()
        assert result["calls"] == []

    @pytest.mark.asyncio
    async def test_get_current_calls_with_calls(self):
        """get_current_calls() should return call info."""
        hal = self._make_hal()
        await hal.dial("+15551234567")
        result = await hal.get_current_calls()
        assert len(result["calls"]) == 1
        assert result["calls"][0]["number"] == "+15551234567"
        assert result["calls"][0]["state"] == CallState.DIALING.value

    @pytest.mark.asyncio
    async def test_call_index_increments(self):
        """Each call should get a unique index."""
        hal = self._make_hal()
        await hal.dial("+15551111111")
        await hal.dial("+15552222222")
        indices = [c.index for c in hal.voice_calls]
        assert len(set(indices)) == 2

    @pytest.mark.asyncio
    async def test_power_off_clears_calls(self):
        """power_off() should clear voice calls."""
        hal = self._make_hal()
        hal.voice_calls.append(VoiceCall(index=1, state=CallState.ACTIVE))
        await hal.power_off()
        assert len(hal.voice_calls) == 0


# =============================================================================
# VoLTECallManager tests
# =============================================================================

class TestVoLTECallManager:
    """Test VoLTE call manager lifecycle."""

    def _make_manager(self):
        config = VoLTEConfig(
            pcscf_address="172.28.0.43",
            pcscf_port=5060,
            impu="sip:001010000000001@ims.example.com",
            impi="001010000000001@ims.example.com",
            home_domain="ims.example.com",
        )
        mgr = VoLTECallManager(config)
        # Mock the SIP client
        mgr._sip_client = MagicMock()
        mgr._sip_client.transport = MagicMock()
        mgr._sip_client.transport.send = AsyncMock()
        mgr._sip_client.local_ip = "10.45.0.2"
        mgr._sip_client.local_port = 5060
        mgr._sip_client._pending_responses = {}
        mgr._started = True
        return mgr

    def test_rtp_port_allocation(self):
        """RTP ports should be allocated as even numbers."""
        mgr = self._make_manager()
        port1 = mgr._allocate_rtp_port()
        port2 = mgr._allocate_rtp_port()
        assert port1 % 2 == 0
        assert port2 % 2 == 0
        assert port2 == port1 + 2

    def test_get_calls_empty(self):
        """get_calls() should return empty list when no calls."""
        mgr = self._make_manager()
        assert mgr.get_calls() == []

    def test_get_calls_with_call(self):
        """get_calls() should return call info."""
        mgr = self._make_manager()
        call = VoLTECall(
            sip_call_id="test-call-id",
            state=VoLTECallState.ACTIVE,
            direction="MO",
            remote_number="+15551234567",
            codec="AMR-WB",
            rtp_port=50000,
        )
        mgr._calls["test-call-id"] = call

        calls = mgr.get_calls()
        assert len(calls) == 1
        assert calls[0]["callId"] == "test-call-id"
        assert calls[0]["direction"] == "MO"
        assert calls[0]["state"] == "active"
        assert calls[0]["number"] == "+15551234567"
        assert calls[0]["codec"] == "AMR-WB"

    @pytest.mark.asyncio
    async def test_initiate_call_not_started(self):
        """initiate_call() should fail if manager not started."""
        mgr = self._make_manager()
        mgr._started = False
        result = await mgr.initiate_call("+15551234567", 1)
        assert result is None

    @pytest.mark.asyncio
    async def test_initiate_call_creates_session(self):
        """initiate_call() should create VoLTECall and send INVITE."""
        mgr = self._make_manager()

        # Mock send_request to return 200 OK with SDP
        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
            headers={"Call-ID": "mock-call-id"},
        )
        mgr._sip_client.send_request = AsyncMock(return_value=ok_response)

        call_id = await mgr.initiate_call("+15551234567", 1)
        assert call_id is not None
        assert call_id in mgr._calls
        assert mgr._calls[call_id].state == VoLTECallState.ACTIVE
        assert mgr._calls[call_id].direction == "MO"
        assert mgr._calls[call_id].codec == "AMR-WB"

    @pytest.mark.asyncio
    async def test_initiate_call_sends_ack(self):
        """initiate_call() should send ACK after 200 OK."""
        mgr = self._make_manager()

        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )
        mgr._sip_client.send_request = AsyncMock(return_value=ok_response)

        await mgr.initiate_call("+15551234567", 1)
        # ACK should be sent via transport.send
        mgr._sip_client.transport.send.assert_awaited()

    @pytest.mark.asyncio
    async def test_initiate_call_with_service_route(self):
        """initiate_call() should include Route header from service_route."""
        mgr = self._make_manager()
        mgr.config.service_route = "<sip:scscf.ims.example.com;lr>"

        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )
        mgr._sip_client.send_request = AsyncMock(return_value=ok_response)

        await mgr.initiate_call("+15551234567", 1)

        call_kwargs = mgr._sip_client.send_request.call_args
        headers = call_kwargs.kwargs.get("extra_headers", {})
        assert "Route" in headers
        assert headers["Route"] == "<sip:scscf.ims.example.com;lr>"

    @pytest.mark.asyncio
    async def test_initiate_call_failure(self):
        """initiate_call() should clean up on non-200 response."""
        mgr = self._make_manager()

        error_response = SIPMessage(
            status_code=486,
            reason_phrase="Busy Here",
        )
        mgr._sip_client.send_request = AsyncMock(return_value=error_response)

        call_id = await mgr.initiate_call("+15551234567", 1)
        assert call_id is None
        assert len(mgr._calls) == 0

    @pytest.mark.asyncio
    async def test_initiate_call_timeout(self):
        """initiate_call() should clean up on timeout."""
        mgr = self._make_manager()
        mgr._sip_client.send_request = AsyncMock(side_effect=TimeoutError("timed out"))

        call_id = await mgr.initiate_call("+15551234567", 1)
        assert call_id is None
        assert len(mgr._calls) == 0

    @pytest.mark.asyncio
    async def test_initiate_call_updates_radio_hal(self):
        """initiate_call() should update RadioHAL call state on success."""
        mgr = self._make_manager()
        hal = MagicMock()
        hal.update_call_state = AsyncMock()
        mgr._radio_hal = hal

        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )
        mgr._sip_client.send_request = AsyncMock(return_value=ok_response)

        await mgr.initiate_call("+15551234567", 1)
        hal.update_call_state.assert_awaited_once_with(1, CallState.ACTIVE)

    @pytest.mark.asyncio
    async def test_hangup_call(self):
        """hangup_call() should send BYE and remove call."""
        mgr = self._make_manager()

        call = VoLTECall(
            sip_call_id="hangup-test",
            state=VoLTECallState.ACTIVE,
            remote_uri="sip:15551234567@ims.example.com",
        )
        mgr._calls["hangup-test"] = call

        bye_response = SIPMessage(status_code=200, reason_phrase="OK")
        mgr._sip_client.send_request = AsyncMock(return_value=bye_response)

        result = await mgr.hangup_call("hangup-test")
        assert result is True
        assert "hangup-test" not in mgr._calls

    @pytest.mark.asyncio
    async def test_hangup_nonexistent(self):
        """hangup_call() should return False for unknown call."""
        mgr = self._make_manager()
        result = await mgr.hangup_call("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_answer_call(self):
        """answer_call() should send 200 OK with SDP and set ACTIVE."""
        mgr = self._make_manager()

        invite_msg = SIPMessage(
            method="INVITE",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15551234567@ims.example.com>;tag=abc",
                "To": "<sip:001010000000001@ims.example.com>",
                "CSeq": "1 INVITE",
                "Call-ID": "mt-call-1",
            },
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )

        call = VoLTECall(
            sip_call_id="mt-call-1",
            state=VoLTECallState.RINGING_IN,
            direction="MT",
            remote_number="+15551234567",
            remote_sdp="v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
            local_sdp=build_sdp_offer("10.45.0.2", 50000),
            rtp_port=50000,
        )
        call._invite_msg = invite_msg
        call._invite_addr = ("10.0.0.1", 5060)
        mgr._calls["mt-call-1"] = call

        result = await mgr.answer_call("mt-call-1")
        assert result is True
        assert mgr._calls["mt-call-1"].state == VoLTECallState.ACTIVE

        # Should have sent 200 OK
        mgr._sip_client.transport.send.assert_awaited()

    @pytest.mark.asyncio
    async def test_answer_not_ringing(self):
        """answer_call() should fail if call is not ringing."""
        mgr = self._make_manager()
        call = VoLTECall(
            sip_call_id="test",
            state=VoLTECallState.ACTIVE,
        )
        mgr._calls["test"] = call
        result = await mgr.answer_call("test")
        assert result is False

    @pytest.mark.asyncio
    async def test_handle_incoming_bye(self):
        """Incoming BYE should remove call and notify RadioHAL."""
        mgr = self._make_manager()
        hal = MagicMock()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, sip_call_id="bye-test")
        ]
        hal._send_indication = AsyncMock()
        mgr._radio_hal = hal

        call = VoLTECall(
            sip_call_id="bye-test",
            state=VoLTECallState.ACTIVE,
            radio_call_index=1,
        )
        mgr._calls["bye-test"] = call

        bye_msg = SIPMessage(
            method="BYE",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15551234567@ims.example.com>",
                "To": "<sip:001010000000001@ims.example.com>",
                "Call-ID": "bye-test",
                "CSeq": "2 BYE",
            },
        )

        await mgr._handle_incoming_bye(bye_msg, ("10.0.0.1", 5060))

        assert "bye-test" not in mgr._calls
        # Should send 200 OK
        mgr._sip_client.transport.send.assert_awaited()
        # Should have removed call from RadioHAL
        assert len(hal.voice_calls) == 0
        hal._send_indication.assert_awaited()

    @pytest.mark.asyncio
    async def test_handle_incoming_cancel(self):
        """Incoming CANCEL should remove call and notify RadioHAL."""
        mgr = self._make_manager()
        hal = MagicMock()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.INCOMING, sip_call_id="cancel-test")
        ]
        hal._send_indication = AsyncMock()
        mgr._radio_hal = hal

        call = VoLTECall(
            sip_call_id="cancel-test",
            state=VoLTECallState.RINGING_IN,
        )
        mgr._calls["cancel-test"] = call

        cancel_msg = SIPMessage(
            method="CANCEL",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15551234567@ims.example.com>",
                "To": "<sip:001010000000001@ims.example.com>",
                "Call-ID": "cancel-test",
                "CSeq": "1 CANCEL",
            },
        )

        await mgr._handle_incoming_cancel(cancel_msg, ("10.0.0.1", 5060))

        assert "cancel-test" not in mgr._calls
        mgr._sip_client.transport.send.assert_awaited()
        assert len(hal.voice_calls) == 0

    @pytest.mark.asyncio
    async def test_handle_incoming_invite(self):
        """Incoming INVITE should create MT call and notify RadioHAL."""
        mgr = self._make_manager()
        hal = MagicMock()
        hal.voice_calls = []

        async def _fake_incoming_call(number, call_id):
            vc = VoiceCall(index=1, state=CallState.INCOMING,
                           is_mt=True, number=number, sip_call_id=call_id)
            hal.voice_calls.append(vc)

        hal.incoming_call = AsyncMock(side_effect=_fake_incoming_call)
        mgr._radio_hal = hal

        invite_msg = SIPMessage(
            method="INVITE",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15559876543@ims.example.com>;tag=xyz",
                "To": "<sip:001010000000001@ims.example.com>",
                "Call-ID": "mt-invite-1",
                "CSeq": "1 INVITE",
            },
            body=b"v=0\r\nm=audio 50000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )

        await mgr._handle_incoming_invite(invite_msg, ("10.0.0.1", 5060))

        # Should send 180 Ringing
        mgr._sip_client.transport.send.assert_awaited()

        # Should create a VoLTECall in RINGING_IN state
        assert "mt-invite-1" in mgr._calls
        assert mgr._calls["mt-invite-1"].state == VoLTECallState.RINGING_IN
        assert mgr._calls["mt-invite-1"].direction == "MT"
        assert mgr._calls["mt-invite-1"].radio_call_index == 1

        # Should notify RadioHAL
        hal.incoming_call.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_handle_180_ringing_response(self):
        """180 Ringing should update MO call to RINGING_OUT and notify RadioHAL."""
        mgr = self._make_manager()
        hal = MagicMock()
        hal.update_call_state = AsyncMock()
        mgr._radio_hal = hal

        call = VoLTECall(
            sip_call_id="mo-call-1",
            state=VoLTECallState.INITIATING,
            direction="MO",
            radio_call_index=1,
        )
        mgr._calls["mo-call-1"] = call

        # Set up a pending response future for the call
        future = asyncio.get_event_loop().create_future()
        mgr._sip_client._pending_responses = {"mo-call-1": future}

        ringing_msg = SIPMessage(
            status_code=180,
            reason_phrase="Ringing",
            headers={"Call-ID": "mo-call-1"},
        )

        await mgr._handle_incoming_sip(ringing_msg, ("10.0.0.1", 5060))

        assert call.state == VoLTECallState.RINGING_OUT
        hal.update_call_state.assert_awaited_once_with(1, CallState.ALERTING)

    @pytest.mark.asyncio
    async def test_stop_hangs_up_active_calls(self):
        """stop() should hang up all active calls."""
        mgr = self._make_manager()

        call = VoLTECall(
            sip_call_id="active-call",
            state=VoLTECallState.ACTIVE,
            remote_uri="sip:15551234567@ims.example.com",
        )
        mgr._calls["active-call"] = call

        bye_response = SIPMessage(status_code=200, reason_phrase="OK")
        mgr._sip_client.send_request = AsyncMock(return_value=bye_response)
        mgr._sip_client.stop = AsyncMock()

        await mgr.stop()
        mgr._sip_client.send_request.assert_awaited()
        assert mgr._started is False


# =============================================================================
# VoLTESession (legacy) tests
# =============================================================================

class TestVoLTESession:
    """Test legacy VoLTESession class."""

    def test_build_sdp_offer(self):
        """VoLTESession.build_sdp_offer() should use module-level function."""
        from ims.registration import IMSCredentials
        creds = IMSCredentials(
            impi="test@ims.example.com",
            impu="sip:test@ims.example.com",
            home_domain="ims.example.com",
            ki=b"\x00" * 16,
            opc=b"\x00" * 16,
        )
        session = VoLTESession(creds, VoLTEConfig())
        sdp = session.build_sdp_offer("10.0.0.1", 50000)
        assert "v=0\r\n" in sdp
        assert "AMR-WB" in sdp

    def test_get_status_not_initialized(self):
        """get_status() before registration should show not_initialized."""
        from ims.registration import IMSCredentials
        creds = IMSCredentials(
            impi="test@ims.example.com",
            impu="sip:test@ims.example.com",
            home_domain="ims.example.com",
            ki=b"\x00" * 16,
            opc=b"\x00" * 16,
        )
        session = VoLTESession(creds, VoLTEConfig())
        status = session.get_status()
        assert status["registered"] is False
        assert status["state"] == "not_initialized"


# =============================================================================
# Module-level state tests
# =============================================================================

class TestModuleState:
    """Test module-level get_volte_state()."""

    def test_get_volte_state_returns_dict(self):
        state = get_volte_state()
        assert isinstance(state, dict)
        assert "enabled" in state
        assert "active_calls" in state
        assert "total_calls" in state

    def test_get_volte_state_is_copy(self):
        """get_volte_state() should return a copy."""
        state1 = get_volte_state()
        state1["enabled"] = "modified"
        state2 = get_volte_state()
        assert state2["enabled"] != "modified"


# =============================================================================
# RIL Bridge DIAL/HANGUP/ANSWER handler tests
# =============================================================================

class TestRILBridgeVoiceHandlers:
    """Test RIL bridge voice call request handlers."""

    def _make_bridge(self):
        from hal.ril_bridge import RILBridge, RILMessage, RILRequest
        bridge = RILBridge.__new__(RILBridge)
        bridge.host = "127.0.0.1"
        bridge.port = 18000
        bridge._server = None
        bridge._clients = []
        bridge.radio_hal = RadioHAL.__new__(RadioHAL)
        bridge.radio_hal.voice_calls = []
        bridge.radio_hal._next_call_index = 1
        bridge.radio_hal._call_manager = None
        bridge.radio_hal._indication_callback = AsyncMock()
        bridge.radio_hal._sms_service = None
        bridge.radio_hal.euicc_socket = "/run/vphone/euicc.sock"
        bridge.radio_hal.radio_state = 10
        bridge.radio_hal.sim_status = MagicMock()
        bridge.radio_hal.registration = MagicMock()
        bridge.radio_hal.data_calls = []
        bridge.radio_hal.imei = "123456789012345"
        bridge.radio_hal._registration_task = None
        bridge.radio_hal._cf_manager = None
        bridge.radio_hal._ussd_handler = None
        bridge.radio_hal._muted = False
        return bridge

    @pytest.mark.asyncio
    async def test_dial_handler(self):
        """DIAL handler should route to RadioHAL.dial()."""
        bridge = self._make_bridge()
        result = await bridge._handle_dial({"address": "+15551234567", "clir": 0})
        assert result["success"] is True
        assert len(bridge.radio_hal.voice_calls) == 1

    @pytest.mark.asyncio
    async def test_hangup_handler(self):
        """HANGUP handler should route to RadioHAL.hangup()."""
        bridge = self._make_bridge()
        await bridge.radio_hal.dial("+15551234567")
        idx = bridge.radio_hal.voice_calls[0].index
        result = await bridge._handle_hangup({"gsmIndex": idx})
        assert result["success"] is True
        assert len(bridge.radio_hal.voice_calls) == 0

    @pytest.mark.asyncio
    async def test_answer_handler(self):
        """ANSWER handler should route to RadioHAL.answer()."""
        bridge = self._make_bridge()
        await bridge.radio_hal.incoming_call("+15559876543", "call-id-1")
        result = await bridge._handle_answer({})
        assert result["success"] is True
        assert bridge.radio_hal.voice_calls[0].state == CallState.ACTIVE

    @pytest.mark.asyncio
    async def test_dial_in_handler_map(self):
        """DIAL should be in the handler map."""
        from hal.ril_bridge import RILBridge, RILMessage, RILRequest
        bridge = self._make_bridge()
        msg = RILMessage(
            msg_type=0, serial=1, request_id=RILRequest.DIAL,
            data={"address": "+15551234567"},
        )
        resp = await bridge._process_request(msg)
        assert resp.data.get("success") is True

    @pytest.mark.asyncio
    async def test_hangup_in_handler_map(self):
        """HANGUP should be in the handler map."""
        from hal.ril_bridge import RILBridge, RILMessage, RILRequest
        bridge = self._make_bridge()
        await bridge.radio_hal.dial("+15551234567")
        idx = bridge.radio_hal.voice_calls[0].index
        msg = RILMessage(
            msg_type=0, serial=2, request_id=RILRequest.HANGUP,
            data={"gsmIndex": idx},
        )
        resp = await bridge._process_request(msg)
        assert resp.data.get("success") is True

    @pytest.mark.asyncio
    async def test_answer_in_handler_map(self):
        """ANSWER should be in the handler map."""
        from hal.ril_bridge import RILBridge, RILMessage, RILRequest
        bridge = self._make_bridge()
        await bridge.radio_hal.incoming_call("+15559876543", "call-id")
        msg = RILMessage(
            msg_type=0, serial=3, request_id=RILRequest.ANSWER,
            data={},
        )
        resp = await bridge._process_request(msg)
        assert resp.data.get("success") is True


# =============================================================================
# Service-Route storage tests
# =============================================================================

class TestServiceRouteStorage:
    """Test that IMSRegistration stores Service-Route from 200 OK."""

    def test_service_route_initialized_none(self):
        from ims.registration import IMSRegistration, IMSCredentials, IMSConfig
        creds = IMSCredentials(
            impi="test@ims.example.com",
            impu="sip:test@ims.example.com",
            home_domain="ims.example.com",
            ki=b"\x00" * 16,
            opc=b"\x00" * 16,
        )
        reg = IMSRegistration(creds, IMSConfig())
        assert reg.service_route is None

    def test_process_200ok_stores_service_route(self):
        from ims.registration import IMSRegistration, IMSCredentials, IMSConfig
        creds = IMSCredentials(
            impi="test@ims.example.com",
            impu="sip:test@ims.example.com",
            home_domain="ims.example.com",
            ki=b"\x00" * 16,
            opc=b"\x00" * 16,
        )
        reg = IMSRegistration(creds, IMSConfig())

        response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Service-Route": "<sip:scscf.ims.example.com;lr>",
                "P-Associated-URI": "<sip:test@ims.example.com>",
            },
        )
        reg._process_200ok(response)
        assert reg.service_route == "<sip:scscf.ims.example.com;lr>"

    def test_process_200ok_no_service_route(self):
        from ims.registration import IMSRegistration, IMSCredentials, IMSConfig
        creds = IMSCredentials(
            impi="test@ims.example.com",
            impu="sip:test@ims.example.com",
            home_domain="ims.example.com",
            ki=b"\x00" * 16,
            opc=b"\x00" * 16,
        )
        reg = IMSRegistration(creds, IMSConfig())

        response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={},
        )
        reg._process_200ok(response)
        assert reg.service_route is None


# =============================================================================
# Management API VoLTE endpoint tests
# =============================================================================

class TestManagementAPIVoLTE:
    """Test management API VoLTE endpoints."""

    @pytest.mark.asyncio
    async def test_volte_status_endpoint_exists(self):
        """The /status/volte endpoint should exist in the FastAPI app."""
        from hal.management_api import app
        routes = [r.path for r in app.routes]
        assert "/status/volte" in routes

    @pytest.mark.asyncio
    async def test_calls_dial_endpoint_exists(self):
        """The /calls/dial endpoint should exist."""
        from hal.management_api import app
        routes = [r.path for r in app.routes]
        assert "/calls/dial" in routes

    @pytest.mark.asyncio
    async def test_calls_hangup_endpoint_exists(self):
        """The /calls/hangup endpoint should exist."""
        from hal.management_api import app
        routes = [r.path for r in app.routes]
        assert "/calls/hangup" in routes

    def test_dial_request_model(self):
        """DialRequest should have a 'number' field."""
        from hal.management_api import DialRequest
        req = DialRequest(number="+15551234567")
        assert req.number == "+15551234567"


# =============================================================================
# IMS __init__ VoLTE manager ref tests
# =============================================================================

class TestVoLTEManagerRef:
    """Test module-level VoLTE manager reference."""

    def test_ref_exists(self):
        from ims import _volte_manager_ref
        assert hasattr(_volte_manager_ref, "instance")

    def test_ref_default_none(self):
        from ims import _VoLTEManagerRef
        ref = _VoLTEManagerRef()
        assert ref.instance is None


# =============================================================================
# End-to-end call flow tests
# =============================================================================

class TestE2ECallFlow:
    """Test end-to-end call flows through RadioHAL → VoLTECallManager."""

    def _make_wired_setup(self):
        """Create a RadioHAL + VoLTECallManager wired together."""
        hal = RadioHAL.__new__(RadioHAL)
        hal.voice_calls = []
        hal._next_call_index = 1
        hal._call_manager = None
        hal._indication_callback = AsyncMock()
        hal._sms_service = None
        hal.euicc_socket = "/run/vphone/euicc.sock"
        hal.radio_state = 10
        hal.sim_status = MagicMock()
        hal.registration = MagicMock()
        hal.data_calls = []
        hal.imei = "123456789012345"
        hal._registration_task = None
        hal._cf_manager = None
        hal._ussd_handler = None
        hal._muted = False

        config = VoLTEConfig(
            pcscf_address="172.28.0.43",
            pcscf_port=5060,
            impu="sip:001010000000001@ims.example.com",
            impi="001010000000001@ims.example.com",
            home_domain="ims.example.com",
        )
        mgr = VoLTECallManager(config)
        mgr._sip_client = MagicMock()
        mgr._sip_client.transport = MagicMock()
        mgr._sip_client.transport.send = AsyncMock()
        mgr._sip_client.local_ip = "10.45.0.2"
        mgr._sip_client.local_port = 5060
        mgr._sip_client._pending_responses = {}
        mgr._started = True

        # Wire them together
        hal.set_call_manager(mgr)
        mgr.set_radio_hal(hal)

        return hal, mgr

    @pytest.mark.asyncio
    async def test_mo_call_e2e(self):
        """MO call: dial() → INVITE → 200 OK → ACK → ACTIVE."""
        hal, mgr = self._make_wired_setup()

        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )
        mgr._sip_client.send_request = AsyncMock(return_value=ok_response)

        result = await hal.dial("+15551234567")
        assert result["success"] is True
        assert len(hal.voice_calls) == 1
        assert hal.voice_calls[0].state == CallState.ACTIVE
        assert hal.voice_calls[0].sip_call_id != ""

    @pytest.mark.asyncio
    async def test_mt_call_e2e(self):
        """MT call: INVITE → RadioHAL ring → answer() → 200 OK → ACTIVE."""
        hal, mgr = self._make_wired_setup()

        invite_msg = SIPMessage(
            method="INVITE",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15559876543@ims.example.com>;tag=xyz",
                "To": "<sip:001010000000001@ims.example.com>",
                "Call-ID": "mt-e2e-1",
                "CSeq": "1 INVITE",
            },
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )

        # Handle incoming INVITE
        await mgr._handle_incoming_invite(invite_msg, ("10.0.0.1", 5060))

        # RadioHAL should have an INCOMING call
        assert len(hal.voice_calls) == 1
        assert hal.voice_calls[0].state == CallState.INCOMING
        assert hal.voice_calls[0].is_mt is True

        # Android answers
        result = await hal.answer()
        assert result["success"] is True
        assert hal.voice_calls[0].state == CallState.ACTIVE

        # VoLTECallManager should have the call as ACTIVE
        assert mgr._calls["mt-e2e-1"].state == VoLTECallState.ACTIVE

    @pytest.mark.asyncio
    async def test_remote_hangup_e2e(self):
        """Remote hangup: active call → BYE → call removed."""
        hal, mgr = self._make_wired_setup()

        # Set up an active call
        invite_msg = SIPMessage(
            method="INVITE",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15559876543@ims.example.com>;tag=xyz",
                "To": "<sip:001010000000001@ims.example.com>",
                "Call-ID": "remote-bye-1",
                "CSeq": "1 INVITE",
            },
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )
        await mgr._handle_incoming_invite(invite_msg, ("10.0.0.1", 5060))
        await hal.answer()

        assert len(hal.voice_calls) == 1

        # Remote sends BYE
        bye_msg = SIPMessage(
            method="BYE",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "From": "<sip:15559876543@ims.example.com>",
                "To": "<sip:001010000000001@ims.example.com>",
                "Call-ID": "remote-bye-1",
                "CSeq": "2 BYE",
            },
        )
        await mgr._handle_incoming_bye(bye_msg, ("10.0.0.1", 5060))

        # Call should be removed from both
        assert "remote-bye-1" not in mgr._calls
        assert len(hal.voice_calls) == 0

    @pytest.mark.asyncio
    async def test_local_hangup_e2e(self):
        """Local hangup: active call → hangup() → BYE → call removed."""
        hal, mgr = self._make_wired_setup()

        ok_response = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            body=b"v=0\r\na=rtpmap:96 AMR-WB/16000/1\r\n",
        )
        mgr._sip_client.send_request = AsyncMock(return_value=ok_response)

        await hal.dial("+15551234567")
        assert len(hal.voice_calls) == 1
        call_index = hal.voice_calls[0].index
        sip_call_id = hal.voice_calls[0].sip_call_id

        # Now hangup
        bye_response = SIPMessage(status_code=200, reason_phrase="OK")
        mgr._sip_client.send_request = AsyncMock(return_value=bye_response)

        result = await hal.hangup(call_index)
        assert result["success"] is True
        assert len(hal.voice_calls) == 0
        assert sip_call_id not in mgr._calls
