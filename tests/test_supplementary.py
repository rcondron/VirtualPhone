"""Tests for Phase 8: Supplementary Services & Call Features.

Tests cover:
- Call Forwarding rules (CFU, CFB, CFNR, CFNRc)
- Call Forwarding actions (set, enable, disable, erase, query)
- Call Forwarding evaluation (should_forward)
- USSD code handling (*#06#, call forwarding MMI codes)
- USSD session lifecycle
- Media hold/resume (direction control, RTP suppression)
- VoLTE hold_call / resume_call / swap_calls
- VoLTE conference (merge active + held)
- VoLTE transfer (SIP REFER)
- RadioHAL supplementary handlers (switch, conference, separate, USSD, CF, mute)
- RadioHAL call waiting (incoming while active)
- RIL bridge new request IDs
- Management API supplementary endpoints
- SDP direction attribute in build_sdp_offer
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ims.supplementary import (
    CallForwardReason, CallForwardAction, CallForwardRule,
    CallForwardingManager, USSDHandler, USSDState, USSDSession,
    get_supplementary_state, update_supplementary_state,
)
from ims.media import MediaSession
from ims.rtp import PT_AMR_WB
from ims.volte import (
    VoLTECallManager, VoLTEConfig, VoLTECall, VoLTECallState,
    build_sdp_offer,
)
from hal.radio_hal import RadioHAL, CallState, VoiceCall
from hal.ril_bridge import RILRequest, RILUnsol


# =============================================================================
# Call Forwarding Manager Tests
# =============================================================================

class TestCallForwardReason:
    """Test call forwarding reason enumeration."""

    def test_reason_values(self):
        assert CallForwardReason.UNCONDITIONAL.value == 0
        assert CallForwardReason.BUSY.value == 1
        assert CallForwardReason.NO_REPLY.value == 2
        assert CallForwardReason.NOT_REACHABLE.value == 3
        assert CallForwardReason.ALL.value == 4
        assert CallForwardReason.ALL_CONDITIONAL.value == 5


class TestCallForwardRule:
    """Test call forwarding rule dataclass."""

    def test_default_rule(self):
        rule = CallForwardRule()
        assert rule.reason == CallForwardReason.UNCONDITIONAL
        assert rule.enabled == False
        assert rule.number == ""
        assert rule.time_seconds == 20

    def test_to_dict(self):
        rule = CallForwardRule(
            reason=CallForwardReason.BUSY,
            enabled=True,
            number="+1234567890",
            time_seconds=30,
        )
        d = rule.to_dict()
        assert d["status"] == 1
        assert d["reason"] == 1
        assert d["number"] == "+1234567890"
        assert d["timeSeconds"] == 30
        assert d["serviceClass"] == 1

    def test_to_dict_disabled(self):
        rule = CallForwardRule(enabled=False)
        assert rule.to_dict()["status"] == 0


class TestCallForwardingManager:
    """Test call forwarding rule management."""

    def test_set_rule(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+1234567890")
        rules = cf.query_rule(CallForwardReason.UNCONDITIONAL)
        assert len(rules) == 1
        assert rules[0]["status"] == 1
        assert rules[0]["number"] == "+1234567890"

    def test_enable_existing_rule(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.BUSY, "+111")
        cf.disable_rule(CallForwardReason.BUSY)
        assert not cf.query_rule(CallForwardReason.BUSY)[0]["status"]
        cf.enable_rule(CallForwardReason.BUSY)
        assert cf.query_rule(CallForwardReason.BUSY)[0]["status"] == 1

    def test_enable_nonexistent_rule(self):
        cf = CallForwardingManager()
        assert cf.enable_rule(CallForwardReason.BUSY) == False

    def test_disable_rule(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.NO_REPLY, "+222", time_seconds=25)
        assert cf.disable_rule(CallForwardReason.NO_REPLY) == True
        rules = cf.query_rule(CallForwardReason.NO_REPLY)
        assert rules[0]["status"] == 0
        # Number is preserved
        assert rules[0]["number"] == "+222"

    def test_disable_nonexistent(self):
        cf = CallForwardingManager()
        assert cf.disable_rule(CallForwardReason.BUSY) == False

    def test_erase_rule(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+333")
        assert cf.erase_rule(CallForwardReason.UNCONDITIONAL) == True
        assert len(cf.query_rule(CallForwardReason.UNCONDITIONAL)) == 0

    def test_erase_all(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+1")
        cf.set_rule(CallForwardReason.BUSY, "+2")
        cf.set_rule(CallForwardReason.NO_REPLY, "+3")
        cf.erase_rule(CallForwardReason.ALL)
        assert len(cf.get_all_rules()) == 0

    def test_erase_all_conditional(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+1")
        cf.set_rule(CallForwardReason.BUSY, "+2")
        cf.set_rule(CallForwardReason.NO_REPLY, "+3")
        cf.set_rule(CallForwardReason.NOT_REACHABLE, "+4")
        cf.erase_rule(CallForwardReason.ALL_CONDITIONAL)
        # Unconditional should remain
        assert len(cf.get_all_rules()) == 1
        assert cf.query_rule(CallForwardReason.UNCONDITIONAL)[0]["number"] == "+1"

    def test_query_rule_not_found(self):
        cf = CallForwardingManager()
        assert cf.query_rule(CallForwardReason.BUSY) == []

    def test_query_all(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+1")
        cf.set_rule(CallForwardReason.BUSY, "+2")
        rules = cf.query_rule(CallForwardReason.ALL)
        assert len(rules) == 2

    def test_query_all_conditional(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+1")
        cf.set_rule(CallForwardReason.BUSY, "+2")
        cf.set_rule(CallForwardReason.NO_REPLY, "+3")
        rules = cf.query_rule(CallForwardReason.ALL_CONDITIONAL)
        assert len(rules) == 2  # BUSY + NO_REPLY, not UNCONDITIONAL

    def test_should_forward_cfu(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+999")
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) == "+999"
        # CFU overrides conditional reasons too
        assert cf.should_forward(CallForwardReason.BUSY) == "+999"

    def test_should_forward_cfb(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.BUSY, "+888")
        assert cf.should_forward(CallForwardReason.BUSY) == "+888"
        # No CFU, so other reasons return None
        assert cf.should_forward(CallForwardReason.NO_REPLY) is None

    def test_should_forward_disabled(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+999")
        cf.disable_rule(CallForwardReason.UNCONDITIONAL)
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) is None

    def test_should_forward_no_rules(self):
        cf = CallForwardingManager()
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) is None

    def test_get_all_rules(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+1")
        cf.set_rule(CallForwardReason.BUSY, "+2")
        rules = cf.get_all_rules()
        assert len(rules) == 2

    def test_time_seconds_cfnr(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.NO_REPLY, "+555", time_seconds=30)
        rules = cf.query_rule(CallForwardReason.NO_REPLY)
        assert rules[0]["timeSeconds"] == 30


# =============================================================================
# USSD Handler Tests
# =============================================================================

class TestUSSDHandler:
    """Test USSD code processing."""

    def test_imei_query(self):
        handler = USSDHandler()
        handler.set_imei("123456789012345")
        result = handler.send_ussd("*#06#")
        assert result["type"] == 0
        assert "123456789012345" in result["message"]

    def test_imei_query_alt(self):
        handler = USSDHandler()
        result = handler.send_ussd("*#06*#")
        assert "IMEI" in result["message"]

    def test_unknown_code(self):
        handler = USSDHandler()
        result = handler.send_ussd("*#999999#")
        assert result["type"] == 2  # terminated

    def test_phone_info_code(self):
        handler = USSDHandler()
        result = handler.send_ussd("*#*#4636#*#*")
        assert result["type"] == 0
        assert "Virtual Phone" in result["message"]

    def test_cf_set_unconditional(self):
        cf = CallForwardingManager()
        handler = USSDHandler(cf)
        result = handler.send_ussd("*21*+1234567890#")
        assert result["type"] == 0
        assert "Registered" in result["message"]
        # Verify rule was set
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) == "+1234567890"

    def test_cf_set_with_double_star(self):
        cf = CallForwardingManager()
        handler = USSDHandler(cf)
        result = handler.send_ussd("**21*+9876543210#")
        assert "Registered" in result["message"]
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) == "+9876543210"

    def test_cf_query_active(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+111")
        handler = USSDHandler(cf)
        result = handler.send_ussd("*#21#")
        assert "Active" in result["message"]
        assert "+111" in result["message"]

    def test_cf_query_inactive(self):
        cf = CallForwardingManager()
        handler = USSDHandler(cf)
        result = handler.send_ussd("*#21#")
        assert "Not active" in result["message"]

    def test_cf_deactivate(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+111")
        handler = USSDHandler(cf)
        result = handler.send_ussd("#21#")
        assert "Deactivated" in result["message"]
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) is None

    def test_cf_erase(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+111")
        handler = USSDHandler(cf)
        result = handler.send_ussd("##21#")
        assert "Erased" in result["message"]
        assert len(cf.get_all_rules()) == 0

    def test_cf_set_busy(self):
        cf = CallForwardingManager()
        handler = USSDHandler(cf)
        handler.send_ussd("*67*+555#")
        assert cf.should_forward(CallForwardReason.BUSY) == "+555"

    def test_cf_set_no_reply(self):
        cf = CallForwardingManager()
        handler = USSDHandler(cf)
        handler.send_ussd("*61*+666#")
        assert cf.should_forward(CallForwardReason.NO_REPLY) == "+666"

    def test_cf_set_not_reachable(self):
        cf = CallForwardingManager()
        handler = USSDHandler(cf)
        handler.send_ussd("*62*+777#")
        assert cf.should_forward(CallForwardReason.NOT_REACHABLE) == "+777"

    def test_cancel_ussd(self):
        handler = USSDHandler()
        handler.send_ussd("*#06#")  # Start a session
        result = handler.cancel_ussd()
        assert result["success"] == True

    def test_balance_inquiry(self):
        handler = USSDHandler()
        result = handler.send_ussd("*100#")
        assert result["type"] == 0
        assert "Balance" in result["message"]


# =============================================================================
# Module-level State Tests
# =============================================================================

class TestSupplementaryState:
    """Test module-level supplementary state."""

    def test_get_state_returns_dict(self):
        state = get_supplementary_state()
        assert isinstance(state, dict)
        assert "call_forwarding_rules" in state
        assert "ussd_session_active" in state
        assert "held_calls" in state
        assert "conference_calls" in state

    def test_update_state(self):
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+111")
        update_supplementary_state(cf_manager=cf, held=1, conference=0)
        state = get_supplementary_state()
        assert state["held_calls"] == 1
        assert len(state["call_forwarding_rules"]) == 1


# =============================================================================
# Media Hold/Resume Tests
# =============================================================================

class TestMediaHoldResume:
    """Test media session hold and resume."""

    @pytest.mark.asyncio
    async def test_hold_sets_state(self):
        session = MediaSession()
        await session.start(62000, "127.0.0.1", 62002)
        assert session.is_held == False
        session.hold()
        assert session.is_held == True
        assert session.direction == "sendonly"
        await session.stop()

    @pytest.mark.asyncio
    async def test_resume_clears_hold(self):
        session = MediaSession()
        await session.start(62100, "127.0.0.1", 62102)
        session.hold()
        session.resume()
        assert session.is_held == False
        assert session.direction == "sendrecv"
        await session.stop()

    @pytest.mark.asyncio
    async def test_hold_blocks_send_frame(self):
        session = MediaSession()
        await session.start(62200, "127.0.0.1", 62202)
        session.hold()
        session.send_frame(b"\x00" * 60)
        assert session.stats.packets_sent == 0  # Blocked by hold
        await session.stop()

    @pytest.mark.asyncio
    async def test_resume_allows_send_frame(self):
        session = MediaSession()
        await session.start(62300, "127.0.0.1", 62302)
        session.hold()
        session.resume()
        session.send_frame(b"\x00" * 60)
        assert session.stats.packets_sent == 1
        await session.stop()

    @pytest.mark.asyncio
    async def test_get_stats_includes_hold(self):
        session = MediaSession()
        await session.start(62400, "127.0.0.1", 62402)
        session.hold()
        stats = session.get_stats()
        assert stats["held"] == True
        assert stats["direction"] == "sendonly"
        await session.stop()

    @pytest.mark.asyncio
    async def test_hold_not_active_noop(self):
        session = MediaSession()
        session.hold()  # Not started — should be a no-op
        assert session.is_held == False


# =============================================================================
# SDP Direction Tests
# =============================================================================

class TestBuildSDPOffer:
    """Test SDP offer building with direction attribute."""

    def test_default_direction_is_sendrecv(self):
        sdp = build_sdp_offer("10.0.0.1", 50000)
        assert "a=sendrecv" in sdp

    def test_sendonly_for_hold(self):
        sdp = build_sdp_offer("10.0.0.1", 50000, direction="sendonly")
        assert "a=sendonly" in sdp
        assert "a=sendrecv" not in sdp

    def test_inactive_direction(self):
        sdp = build_sdp_offer("10.0.0.1", 50000, direction="inactive")
        assert "a=inactive" in sdp

    def test_recvonly_direction(self):
        sdp = build_sdp_offer("10.0.0.1", 50000, direction="recvonly")
        assert "a=recvonly" in sdp

    def test_sdp_still_has_codecs(self):
        sdp = build_sdp_offer("10.0.0.1", 50000, direction="sendonly")
        assert "AMR-WB" in sdp
        assert "telephone-event" in sdp


# =============================================================================
# VoLTE Hold/Resume Tests
# =============================================================================

class TestVoLTEHoldResume:
    """Test VoLTE call manager hold/resume."""

    def _make_manager(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        return VoLTECallManager(config)

    @pytest.mark.asyncio
    async def test_hold_active_call(self):
        mgr = self._make_manager()
        call = VoLTECall(
            sip_call_id="hold-1",
            state=VoLTECallState.ACTIVE,
            rtp_port=50000,
        )
        mgr._calls["hold-1"] = call

        result = await mgr.hold_call("hold-1")
        assert result == True
        assert call.state == VoLTECallState.HELD

    @pytest.mark.asyncio
    async def test_hold_non_active_fails(self):
        mgr = self._make_manager()
        call = VoLTECall(
            sip_call_id="hold-2",
            state=VoLTECallState.RINGING_IN,
        )
        mgr._calls["hold-2"] = call

        result = await mgr.hold_call("hold-2")
        assert result == False

    @pytest.mark.asyncio
    async def test_hold_unknown_call_fails(self):
        mgr = self._make_manager()
        result = await mgr.hold_call("nonexistent")
        assert result == False

    @pytest.mark.asyncio
    async def test_resume_held_call(self):
        mgr = self._make_manager()
        call = VoLTECall(
            sip_call_id="resume-1",
            state=VoLTECallState.HELD,
            rtp_port=50000,
        )
        mgr._calls["resume-1"] = call

        result = await mgr.resume_call("resume-1")
        assert result == True
        assert call.state == VoLTECallState.ACTIVE

    @pytest.mark.asyncio
    async def test_resume_non_held_fails(self):
        mgr = self._make_manager()
        call = VoLTECall(
            sip_call_id="resume-2",
            state=VoLTECallState.ACTIVE,
        )
        mgr._calls["resume-2"] = call

        result = await mgr.resume_call("resume-2")
        assert result == False

    @pytest.mark.asyncio
    async def test_hold_pauses_media(self):
        mgr = self._make_manager()
        session = MediaSession(ssrc=0x11111111)
        await session.start(62500, "127.0.0.1", 62502)

        call = VoLTECall(
            sip_call_id="hold-media",
            state=VoLTECallState.ACTIVE,
            media_session=session,
            rtp_port=62500,
        )
        mgr._calls["hold-media"] = call

        await mgr.hold_call("hold-media")
        assert session.is_held == True
        await session.stop()

    @pytest.mark.asyncio
    async def test_resume_resumes_media(self):
        mgr = self._make_manager()
        session = MediaSession(ssrc=0x22222222)
        await session.start(62600, "127.0.0.1", 62602)
        session.hold()

        call = VoLTECall(
            sip_call_id="resume-media",
            state=VoLTECallState.HELD,
            media_session=session,
            rtp_port=62600,
        )
        mgr._calls["resume-media"] = call

        await mgr.resume_call("resume-media")
        assert session.is_held == False
        await session.stop()


# =============================================================================
# VoLTE Swap Tests
# =============================================================================

class TestVoLTESwap:
    """Test swap between active and held calls."""

    @pytest.mark.asyncio
    async def test_swap_active_and_held(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        active = VoLTECall(
            sip_call_id="swap-active",
            state=VoLTECallState.ACTIVE,
            rtp_port=50000,
        )
        held = VoLTECall(
            sip_call_id="swap-held",
            state=VoLTECallState.HELD,
            rtp_port=50002,
        )
        mgr._calls["swap-active"] = active
        mgr._calls["swap-held"] = held

        result = await mgr.swap_calls()
        assert result == True
        assert active.state == VoLTECallState.HELD
        assert held.state == VoLTECallState.ACTIVE

    @pytest.mark.asyncio
    async def test_swap_no_calls(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)
        result = await mgr.swap_calls()
        assert result == False


# =============================================================================
# VoLTE Conference Tests
# =============================================================================

class TestVoLTEConference:
    """Test conference call creation."""

    @pytest.mark.asyncio
    async def test_conference_needs_active_and_held(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        # Only active, no held
        active = VoLTECall(
            sip_call_id="conf-1",
            state=VoLTECallState.ACTIVE,
        )
        mgr._calls["conf-1"] = active
        result = await mgr.conference_calls()
        assert result == False

    @pytest.mark.asyncio
    async def test_conference_merges_calls(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        hal = RadioHAL()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, sip_call_id="conf-a"),
            VoiceCall(index=2, state=CallState.HOLDING, sip_call_id="conf-h"),
        ]
        mgr.set_radio_hal(hal)
        hal._indication_callback = AsyncMock()

        active = VoLTECall(
            sip_call_id="conf-a",
            state=VoLTECallState.ACTIVE,
        )
        held = VoLTECall(
            sip_call_id="conf-h",
            state=VoLTECallState.HELD,
        )
        mgr._calls["conf-a"] = active
        mgr._calls["conf-h"] = held

        result = await mgr.conference_calls()
        assert result == True
        assert held.state == VoLTECallState.ACTIVE

        # Check radio HAL calls are marked multi-party
        for vc in hal.voice_calls:
            assert vc.is_mpty == True


# =============================================================================
# VoLTE Transfer Tests
# =============================================================================

class TestVoLTETransfer:
    """Test call transfer."""

    @pytest.mark.asyncio
    async def test_transfer_not_active_fails(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        call = VoLTECall(
            sip_call_id="xfer-1",
            state=VoLTECallState.RINGING_IN,
        )
        mgr._calls["xfer-1"] = call

        result = await mgr.transfer_call("xfer-1", "+9999")
        assert result == False

    @pytest.mark.asyncio
    async def test_transfer_unknown_call_fails(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)
        result = await mgr.transfer_call("nonexistent", "+9999")
        assert result == False

    @pytest.mark.asyncio
    async def test_transfer_no_sip_client(self):
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)
        call = VoLTECall(
            sip_call_id="xfer-2",
            state=VoLTECallState.ACTIVE,
        )
        mgr._calls["xfer-2"] = call
        result = await mgr.transfer_call("xfer-2", "+9999")
        assert result == False  # No SIP client started


# =============================================================================
# RadioHAL Supplementary Service Tests
# =============================================================================

class TestRadioHALSupplementary:
    """Test RadioHAL supplementary service handlers."""

    @pytest.mark.asyncio
    async def test_switch_holding_and_active(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()

        # Setup: one active, one held
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, sip_call_id="s1"),
            VoiceCall(index=2, state=CallState.HOLDING, sip_call_id="s2"),
        ]

        # Mock call manager
        mock_mgr = MagicMock()
        mock_mgr.swap_calls = AsyncMock(return_value=True)
        hal._call_manager = mock_mgr

        result = await hal.switch_waiting_or_holding_and_active()
        assert result["success"] == True
        mock_mgr.swap_calls.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_switch_with_waiting_call(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()

        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, sip_call_id="s1"),
            VoiceCall(index=2, state=CallState.WAITING, sip_call_id="s2"),
        ]

        mock_mgr = MagicMock()
        mock_mgr.hold_call = AsyncMock(return_value=True)
        mock_mgr.answer_call = AsyncMock(return_value=True)
        hal._call_manager = mock_mgr

        result = await hal.switch_waiting_or_holding_and_active()
        assert result["success"] == True
        # Active call should be put on hold
        assert hal.voice_calls[0].state == CallState.HOLDING
        # Waiting call should become active
        assert hal.voice_calls[1].state == CallState.ACTIVE

    @pytest.mark.asyncio
    async def test_conference(self):
        hal = RadioHAL()
        mock_mgr = MagicMock()
        mock_mgr.conference_calls = AsyncMock(return_value=True)
        hal._call_manager = mock_mgr

        result = await hal.conference()
        assert result["success"] == True

    @pytest.mark.asyncio
    async def test_conference_no_manager(self):
        hal = RadioHAL()
        result = await hal.conference()
        assert result["success"] == False

    @pytest.mark.asyncio
    async def test_separate_connection(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, is_mpty=True, sip_call_id="sep-1"),
        ]
        mock_mgr = MagicMock()
        mock_mgr.hold_call = AsyncMock(return_value=True)
        hal._call_manager = mock_mgr

        result = await hal.separate_connection(1)
        assert result["success"] == True
        assert hal.voice_calls[0].is_mpty == False
        assert hal.voice_calls[0].state == CallState.HOLDING

    @pytest.mark.asyncio
    async def test_separate_not_in_conference(self):
        hal = RadioHAL()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, is_mpty=False),
        ]
        result = await hal.separate_connection(1)
        assert result["success"] == False

    @pytest.mark.asyncio
    async def test_set_mute(self):
        hal = RadioHAL()
        result = await hal.set_mute(True)
        assert result["success"] == True
        result = await hal.get_mute()
        assert result["muted"] == True

    @pytest.mark.asyncio
    async def test_unmute(self):
        hal = RadioHAL()
        await hal.set_mute(True)
        await hal.set_mute(False)
        result = await hal.get_mute()
        assert result["muted"] == False

    @pytest.mark.asyncio
    async def test_send_ussd(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()

        from ims.supplementary import USSDHandler
        handler = USSDHandler()
        hal._ussd_handler = handler

        result = await hal.send_ussd("*#06#")
        assert result["success"] == True
        # Should have sent ON_USSD indication
        hal._indication_callback.assert_awaited()

    @pytest.mark.asyncio
    async def test_send_ussd_no_handler(self):
        hal = RadioHAL()
        result = await hal.send_ussd("*#06#")
        assert result["success"] == False

    @pytest.mark.asyncio
    async def test_cancel_ussd(self):
        from ims.supplementary import USSDHandler
        hal = RadioHAL()
        hal._ussd_handler = USSDHandler()
        result = await hal.cancel_ussd()
        assert result["success"] == True

    @pytest.mark.asyncio
    async def test_set_call_forward(self):
        from ims.supplementary import CallForwardingManager
        hal = RadioHAL()
        cf = CallForwardingManager()
        hal._cf_manager = cf

        result = await hal.set_call_forward(
            action=3,  # register
            reason=0,  # unconditional
            number="+1234567890",
            time_seconds=20,
        )
        assert result["success"] == True
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) == "+1234567890"

    @pytest.mark.asyncio
    async def test_set_call_forward_disable(self):
        from ims.supplementary import CallForwardingManager
        hal = RadioHAL()
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+111")
        hal._cf_manager = cf

        await hal.set_call_forward(action=0, reason=0, number="", time_seconds=0)
        assert cf.should_forward(CallForwardReason.UNCONDITIONAL) is None

    @pytest.mark.asyncio
    async def test_set_call_forward_no_manager(self):
        hal = RadioHAL()
        result = await hal.set_call_forward(
            action=3, reason=0, number="+111", time_seconds=20)
        assert result["success"] == False

    @pytest.mark.asyncio
    async def test_query_call_forward(self):
        from ims.supplementary import CallForwardingManager
        hal = RadioHAL()
        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+999")
        hal._cf_manager = cf

        result = await hal.query_call_forward(reason=0)
        assert len(result["rules"]) == 1
        assert result["rules"][0]["number"] == "+999"

    @pytest.mark.asyncio
    async def test_query_call_forward_no_manager(self):
        hal = RadioHAL()
        result = await hal.query_call_forward(reason=0)
        assert result["rules"] == []


# =============================================================================
# RadioHAL Call Waiting Tests
# =============================================================================

class TestRadioHALCallWaiting:
    """Test call waiting behavior."""

    @pytest.mark.asyncio
    async def test_incoming_while_active_sets_waiting(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()

        # Setup: existing active call
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, sip_call_id="cw-1"),
        ]

        await hal.incoming_call("+5551234", "cw-2")
        # New call should be WAITING, not INCOMING
        assert len(hal.voice_calls) == 2
        assert hal.voice_calls[1].state == CallState.WAITING
        assert hal.voice_calls[1].number == "+5551234"

    @pytest.mark.asyncio
    async def test_incoming_no_active_sets_incoming(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()

        await hal.incoming_call("+5551234", "cw-3")
        assert hal.voice_calls[0].state == CallState.INCOMING

    @pytest.mark.asyncio
    async def test_incoming_with_cfu_forwards(self):
        """Call forwarding unconditional should redirect incoming calls."""
        from ims.supplementary import CallForwardingManager
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()

        cf = CallForwardingManager()
        cf.set_rule(CallForwardReason.UNCONDITIONAL, "+9999")
        hal._cf_manager = cf

        mock_mgr = MagicMock()
        mock_mgr.hangup_call = AsyncMock()
        mock_mgr.initiate_call = AsyncMock(return_value="fwd-call-id")
        hal._call_manager = mock_mgr

        await hal.incoming_call("+5551234", "cfu-test")
        # Should not have added a voice call (it was forwarded)
        assert len(hal.voice_calls) == 0
        mock_mgr.hangup_call.assert_awaited_once_with("cfu-test")
        mock_mgr.initiate_call.assert_awaited_once()


# =============================================================================
# RadioHAL Explicit Call Transfer Tests
# =============================================================================

class TestRadioHALTransfer:
    """Test explicit call transfer via RadioHAL."""

    @pytest.mark.asyncio
    async def test_ect_needs_active_and_held(self):
        hal = RadioHAL()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE),
        ]
        result = await hal.explicit_call_transfer()
        assert result["success"] == False

    @pytest.mark.asyncio
    async def test_ect_success(self):
        hal = RadioHAL()
        hal._indication_callback = AsyncMock()
        hal.voice_calls = [
            VoiceCall(index=1, state=CallState.ACTIVE, number="+111", sip_call_id="ect-a"),
            VoiceCall(index=2, state=CallState.HOLDING, number="+222", sip_call_id="ect-h"),
        ]
        mock_mgr = MagicMock()
        mock_mgr.transfer_call = AsyncMock(return_value=True)
        hal._call_manager = mock_mgr

        result = await hal.explicit_call_transfer()
        assert result["success"] == True
        assert len(hal.voice_calls) == 0


# =============================================================================
# RIL Bridge Request ID Tests
# =============================================================================

class TestRILBridgeSupplementaryIDs:
    """Test that new RIL request IDs are defined."""

    def test_switch_holding_id(self):
        assert RILRequest.SWITCH_WAITING_OR_HOLDING_AND_ACTIVE == 15

    def test_conference_id(self):
        assert RILRequest.CONFERENCE == 16

    def test_send_ussd_id(self):
        assert RILRequest.SEND_USSD == 29

    def test_cancel_ussd_id(self):
        assert RILRequest.CANCEL_USSD == 30

    def test_query_cf_id(self):
        assert RILRequest.QUERY_CALL_FORWARD_STATUS == 33

    def test_set_cf_id(self):
        assert RILRequest.SET_CALL_FORWARD == 34

    def test_separate_connection_id(self):
        assert RILRequest.SEPARATE_CONNECTION == 52

    def test_set_mute_id(self):
        assert RILRequest.SET_MUTE == 53

    def test_get_mute_id(self):
        assert RILRequest.GET_MUTE == 54

    def test_explicit_call_transfer_id(self):
        assert RILRequest.EXPLICIT_CALL_TRANSFER == 72

    def test_on_ussd_unsol(self):
        assert RILUnsol.ON_USSD == 1028


class TestRILBridgeHandlerMap:
    """Test that new handlers are wired in the RIL bridge."""

    def test_handlers_wired(self):
        from hal.ril_bridge import RILBridge
        bridge = RILBridge()
        # Check that handlers exist by calling _process_request
        # We verify by checking that the request_ids map to functions
        handlers = {
            RILRequest.SWITCH_WAITING_OR_HOLDING_AND_ACTIVE: "_handle_switch_holding",
            RILRequest.CONFERENCE: "_handle_conference",
            RILRequest.SEPARATE_CONNECTION: "_handle_separate",
            RILRequest.EXPLICIT_CALL_TRANSFER: "_handle_transfer",
            RILRequest.SEND_USSD: "_handle_send_ussd",
            RILRequest.CANCEL_USSD: "_handle_cancel_ussd",
            RILRequest.QUERY_CALL_FORWARD_STATUS: "_handle_query_cf",
            RILRequest.SET_CALL_FORWARD: "_handle_set_cf",
            RILRequest.SET_MUTE: "_handle_set_mute",
            RILRequest.GET_MUTE: "_handle_get_mute",
        }
        for req_id, method_name in handlers.items():
            assert hasattr(bridge, method_name), \
                f"Missing handler {method_name} for {req_id}"


# =============================================================================
# Management API Endpoint Tests
# =============================================================================

class TestManagementAPISupplementary:
    """Test supplementary service management API endpoints."""

    @pytest.mark.asyncio
    async def test_status_supplementary(self):
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/status/supplementary")
            assert resp.status_code == 200
            data = resp.json()
            assert "call_forwarding_rules" in data
            assert "held_calls" in data

    @pytest.mark.asyncio
    async def test_ussd_send_endpoint(self):
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/ussd/send", json={"code": "*#06#"})
            assert resp.status_code == 200
            data = resp.json()
            assert "IMEI" in data["message"]

    @pytest.mark.asyncio
    async def test_swap_endpoint_exists(self):
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/calls/swap")
            # Will be 503 since no VoLTE manager is running
            assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_conference_endpoint_exists(self):
        from hal.management_api import app
        from httpx import AsyncClient, ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/calls/conference")
            assert resp.status_code == 503


# =============================================================================
# VoLTE re-INVITE Handler Tests
# =============================================================================

class TestVoLTEReInvite:
    """Test re-INVITE handling for remote hold/resume."""

    @pytest.mark.asyncio
    async def test_handle_reinvite_hold(self):
        from ims.sip_client import SIPMessage
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        call = VoLTECall(
            sip_call_id="reinv-1",
            state=VoLTECallState.ACTIVE,
            local_sdp="v=0\r\na=sendrecv\r\n",
            rtp_port=50000,
        )
        mgr._calls["reinv-1"] = call

        msg = SIPMessage(
            method="INVITE",
            request_uri="sip:test@example.com",
            headers={"Call-ID": "reinv-1", "CSeq": "2 INVITE"},
            body=b"v=0\r\na=sendonly\r\n",
        )

        await mgr._handle_reinvite(msg, ("127.0.0.1", 5060), call)
        assert call.state == VoLTECallState.HELD

    @pytest.mark.asyncio
    async def test_handle_reinvite_resume(self):
        from ims.sip_client import SIPMessage
        config = VoLTEConfig(pcscf_address="127.0.0.1")
        mgr = VoLTECallManager(config)

        call = VoLTECall(
            sip_call_id="reinv-2",
            state=VoLTECallState.HELD,
            local_sdp="v=0\r\na=sendonly\r\n",
            rtp_port=50000,
        )
        mgr._calls["reinv-2"] = call

        msg = SIPMessage(
            method="INVITE",
            request_uri="sip:test@example.com",
            headers={"Call-ID": "reinv-2", "CSeq": "3 INVITE"},
            body=b"v=0\r\na=sendrecv\r\n",
        )

        await mgr._handle_reinvite(msg, ("127.0.0.1", 5060), call)
        assert call.state == VoLTECallState.ACTIVE
