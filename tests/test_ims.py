"""Tests for IMS components."""

import asyncio
import pytest

from ims.sip_client import (
    SIPMessage,
    SIPClient,
    SIPDispatcher,
    generate_call_id,
    generate_branch,
    generate_tag,
)
from ims.volte import VoLTESession, VoLTEConfig
from ims.registration import IMSCredentials


class TestSIPMessage:
    def test_parse_request(self):
        """Test parsing a SIP REGISTER request."""
        raw = (
            b"REGISTER sip:ims.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK123\r\n"
            b"From: <sip:user@ims.example.com>;tag=abc\r\n"
            b"To: <sip:user@ims.example.com>\r\n"
            b"Call-ID: 12345@10.0.0.1\r\n"
            b"CSeq: 1 REGISTER\r\n"
            b"Contact: <sip:user@10.0.0.1>\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        msg = SIPMessage.parse(raw)
        assert msg.is_request
        assert msg.method == "REGISTER"
        assert msg.request_uri == "sip:ims.example.com"
        assert msg.call_id == "12345@10.0.0.1"
        assert msg.cseq == "1 REGISTER"

    def test_parse_response(self):
        """Test parsing a SIP 200 OK response."""
        raw = (
            b"SIP/2.0 200 OK\r\n"
            b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK123\r\n"
            b"From: <sip:user@ims.example.com>;tag=abc\r\n"
            b"To: <sip:user@ims.example.com>;tag=xyz\r\n"
            b"Call-ID: 12345@10.0.0.1\r\n"
            b"CSeq: 1 REGISTER\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        msg = SIPMessage.parse(raw)
        assert msg.is_response
        assert msg.status_code == 200
        assert msg.reason_phrase == "OK"

    def test_parse_401(self):
        """Test parsing a 401 Unauthorized with WWW-Authenticate."""
        raw = (
            b"SIP/2.0 401 Unauthorized\r\n"
            b"Via: SIP/2.0/UDP 10.0.0.1:5060\r\n"
            b"Call-ID: test@10.0.0.1\r\n"
            b'WWW-Authenticate: Digest realm="ims.example.com", nonce="abc123", algorithm=AKAv1-MD5\r\n'
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        msg = SIPMessage.parse(raw)
        assert msg.status_code == 401
        assert "Digest" in msg.headers.get("WWW-Authenticate", "")

    def test_serialize_request(self):
        """Test serializing a SIP request."""
        msg = SIPMessage(
            method="REGISTER",
            request_uri="sip:ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1:5060",
                "Call-ID": "test@host",
                "CSeq": "1 REGISTER",
            },
        )
        data = msg.serialize()
        assert b"REGISTER sip:ims.example.com SIP/2.0" in data
        assert b"Call-ID: test@host" in data

    def test_serialize_response(self):
        msg = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={"Content-Length": "0"},
        )
        data = msg.serialize()
        assert b"SIP/2.0 200 OK" in data


class TestSIPHelpers:
    def test_generate_call_id(self):
        cid = generate_call_id()
        assert "@virtualphone" in cid
        assert len(cid) > 16

    def test_generate_branch(self):
        branch = generate_branch()
        assert branch.startswith("z9hG4bK")

    def test_generate_tag(self):
        tag = generate_tag()
        assert len(tag) == 12  # 6 bytes hex

    def test_unique_call_ids(self):
        ids = {generate_call_id() for _ in range(100)}
        assert len(ids) == 100

    def test_unique_branches(self):
        branches = {generate_branch() for _ in range(100)}
        assert len(branches) == 100


class TestSIPAuth:
    def test_build_auth_header(self):
        """Test digest auth header construction."""
        client = SIPClient()
        www_auth = (
            'Digest realm="ims.example.com", '
            'nonce="abc123def456", '
            'algorithm=MD5, '
            'qop="auth"'
        )
        auth = client.build_auth_header(
            www_authenticate=www_auth,
            method="REGISTER",
            uri="sip:ims.example.com",
            username="user@ims.example.com",
            password="secretpass",
        )
        assert 'Digest username="user@ims.example.com"' in auth
        assert 'realm="ims.example.com"' in auth
        assert 'response="' in auth
        assert 'algorithm=MD5' in auth


class TestVoLTESDP:
    def test_build_sdp_offer(self):
        """Test SDP offer generation for VoLTE."""
        creds = IMSCredentials(
            impi="user@ims.example.com",
            impu="sip:user@ims.example.com",
            home_domain="ims.example.com",
            ki=b"\x00" * 16,
            opc=b"\x00" * 16,
        )
        session = VoLTESession(
            credentials=creds,
            config=VoLTEConfig(),
        )

        sdp = session.build_sdp_offer("10.0.0.1", 50000)
        assert "v=0" in sdp
        assert "m=audio 50000" in sdp
        assert "AMR-WB" in sdp
        assert "sendrecv" in sdp


# =============================================================================
# SIP Dispatcher tests
# =============================================================================

class TestSIPDispatcher:
    """Test SIP method-based dispatcher."""

    @pytest.mark.asyncio
    async def test_routes_invite_to_registered_handler(self):
        """INVITE request is routed to the registered INVITE handler."""
        dispatcher = SIPDispatcher()
        received = []

        async def invite_handler(msg, addr):
            received.append(("invite", msg.method))

        dispatcher.register_method("INVITE", invite_handler)

        msg = SIPMessage(method="INVITE", request_uri="sip:test@example.com")
        await dispatcher.dispatch(msg, ("127.0.0.1", 5060))

        assert len(received) == 1
        assert received[0] == ("invite", "INVITE")

    @pytest.mark.asyncio
    async def test_routes_message_to_sms_handler(self):
        """MESSAGE request is routed to the MESSAGE handler."""
        dispatcher = SIPDispatcher()
        received = []

        async def message_handler(msg, addr):
            received.append(msg.method)

        dispatcher.register_method("MESSAGE", message_handler)

        msg = SIPMessage(method="MESSAGE", request_uri="sip:test@example.com")
        await dispatcher.dispatch(msg, ("127.0.0.1", 5060))
        assert received == ["MESSAGE"]

    @pytest.mark.asyncio
    async def test_multiple_methods_coexist(self):
        """Multiple method handlers can coexist without conflict."""
        dispatcher = SIPDispatcher()
        calls = []

        async def invite_h(msg, addr):
            calls.append("invite")

        async def bye_h(msg, addr):
            calls.append("bye")

        async def message_h(msg, addr):
            calls.append("message")

        dispatcher.register_method("INVITE", invite_h)
        dispatcher.register_method("BYE", bye_h)
        dispatcher.register_method("MESSAGE", message_h)

        await dispatcher.dispatch(
            SIPMessage(method="INVITE", request_uri="sip:a@b"), ("1.2.3.4", 5060))
        await dispatcher.dispatch(
            SIPMessage(method="MESSAGE", request_uri="sip:a@b"), ("1.2.3.4", 5060))
        await dispatcher.dispatch(
            SIPMessage(method="BYE", request_uri="sip:a@b"), ("1.2.3.4", 5060))

        assert calls == ["invite", "message", "bye"]

    @pytest.mark.asyncio
    async def test_response_goes_to_response_handlers(self):
        """SIP responses are sent to all registered response handlers."""
        dispatcher = SIPDispatcher()
        responses = []

        async def resp_handler1(msg, addr):
            responses.append(("h1", msg.status_code))

        async def resp_handler2(msg, addr):
            responses.append(("h2", msg.status_code))

        dispatcher.register_response_handler(resp_handler1)
        dispatcher.register_response_handler(resp_handler2)

        msg = SIPMessage(status_code=200, reason_phrase="OK",
                         headers={"Call-ID": "test123"})
        await dispatcher.dispatch(msg, ("127.0.0.1", 5060))

        assert len(responses) == 2
        assert ("h1", 200) in responses
        assert ("h2", 200) in responses

    @pytest.mark.asyncio
    async def test_unregistered_method_uses_default(self):
        """Unregistered method falls back to default handler."""
        dispatcher = SIPDispatcher()
        defaults = []

        async def default_h(msg, addr):
            defaults.append(msg.method)

        dispatcher.set_default_handler(default_h)

        msg = SIPMessage(method="OPTIONS", request_uri="sip:a@b")
        await dispatcher.dispatch(msg, ("127.0.0.1", 5060))
        assert defaults == ["OPTIONS"]

    @pytest.mark.asyncio
    async def test_unregistered_method_no_default_is_noop(self):
        """Unregistered method without default handler is silently ignored."""
        dispatcher = SIPDispatcher()
        msg = SIPMessage(method="OPTIONS", request_uri="sip:a@b")
        # Should not raise
        await dispatcher.dispatch(msg, ("127.0.0.1", 5060))


# =============================================================================
# SIPClient resolve_response tests
# =============================================================================

class TestSIPClientResolveResponse:
    """Test SIPClient.resolve_response() and has_pending_request()."""

    def test_has_pending_request_false_when_empty(self):
        """No pending requests initially."""
        client = SIPClient()
        assert client.has_pending_request("nonexistent") is False

    def test_has_pending_request_true_when_added(self):
        """Returns True when a future is pending for the call-id."""
        client = SIPClient()
        future = asyncio.get_event_loop().create_future()
        client._pending_responses["test-call-id"] = future
        assert client.has_pending_request("test-call-id") is True

    def test_resolve_response_resolves_future(self):
        """resolve_response resolves the pending future."""
        client = SIPClient()
        future = asyncio.get_event_loop().create_future()
        client._pending_responses["cid-123"] = future

        msg = SIPMessage(status_code=200, reason_phrase="OK",
                         headers={"Call-ID": "cid-123"})
        result = client.resolve_response(msg)
        assert result is True
        assert future.done()
        assert future.result() == msg

    def test_resolve_response_returns_false_for_unknown_callid(self):
        """resolve_response returns False for unknown Call-ID."""
        client = SIPClient()
        msg = SIPMessage(status_code=200, reason_phrase="OK",
                         headers={"Call-ID": "unknown"})
        assert client.resolve_response(msg) is False

    def test_resolve_response_ignores_provisional(self):
        """resolve_response returns False for provisional responses (<200)."""
        client = SIPClient()
        future = asyncio.get_event_loop().create_future()
        client._pending_responses["cid-100"] = future

        msg = SIPMessage(status_code=180, reason_phrase="Ringing",
                         headers={"Call-ID": "cid-100"})
        result = client.resolve_response(msg)
        assert result is False
        assert not future.done()
        # Future should still be pending
        assert client.has_pending_request("cid-100")

    def test_resolve_response_removes_from_pending(self):
        """After resolve, the call-id is removed from pending."""
        client = SIPClient()
        future = asyncio.get_event_loop().create_future()
        client._pending_responses["cid-456"] = future

        msg = SIPMessage(status_code=200, reason_phrase="OK",
                         headers={"Call-ID": "cid-456"})
        client.resolve_response(msg)
        assert not client.has_pending_request("cid-456")


# =============================================================================
# VoLTE Call Transfer (SIP REFER) tests
# =============================================================================

from unittest.mock import AsyncMock, MagicMock, patch
from ims.volte import (
    VoLTECallManager, VoLTEConfig, VoLTECall, VoLTECallState,
    _extract_number_from_uri,
)


def _make_manager() -> VoLTECallManager:
    """Create a VoLTECallManager with mock SIP client for testing."""
    config = VoLTEConfig(
        pcscf_address="10.0.0.1",
        pcscf_port=5060,
        impu="sip:user@ims.example.com",
        home_domain="ims.example.com",
    )
    mgr = VoLTECallManager(config)
    mgr._started = True
    mgr._sip_client = MagicMock()
    mgr._sip_client.transport = MagicMock()
    mgr._sip_client.transport.send = AsyncMock()
    mgr._sip_client.send_request = AsyncMock()
    mgr._sip_client.has_pending_request = MagicMock(return_value=False)
    mgr._sip_client.resolve_response = MagicMock(return_value=False)
    return mgr


def _make_call(call_id: str = "test-call-1",
               state: VoLTECallState = VoLTECallState.ACTIVE,
               remote_uri: str = "sip:5551234@ims.example.com",
               remote_number: str = "+5551234") -> VoLTECall:
    """Create a VoLTECall for testing."""
    return VoLTECall(
        sip_call_id=call_id,
        radio_call_index=1,
        state=state,
        direction="MO",
        remote_number=remote_number,
        remote_uri=remote_uri,
        rtp_port=50000,
    )


class TestBlindTransfer:
    """Test blind (unattended) call transfer via SIP REFER."""

    @pytest.mark.asyncio
    async def test_transfer_sends_refer_with_correct_headers(self):
        """transfer_call sends REFER with Refer-To and Referred-By headers."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=202, reason_phrase="Accepted",
            headers={"Call-ID": call.sip_call_id})

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is True

        # Verify REFER was sent
        send_call = mgr._sip_client.send_request.call_args
        assert send_call.kwargs["method"] == "REFER"
        headers = send_call.kwargs["extra_headers"]
        assert "5559999" in headers["Refer-To"]
        assert "Referred-By" in headers

    @pytest.mark.asyncio
    async def test_transfer_accepts_202(self):
        """transfer_call accepts 202 Accepted (standard REFER response)."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=202, reason_phrase="Accepted",
            headers={"Call-ID": call.sip_call_id})

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is True
        # Call should still be in _calls (waiting for NOTIFY)
        assert call.sip_call_id in mgr._calls
        assert getattr(call, "_transfer_pending", False) is True

    @pytest.mark.asyncio
    async def test_transfer_accepts_200(self):
        """transfer_call also accepts 200 OK."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=200, reason_phrase="OK",
            headers={"Call-ID": call.sip_call_id})

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is True

    @pytest.mark.asyncio
    async def test_transfer_fails_on_403(self):
        """transfer_call returns False on 403 Forbidden."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=403, reason_phrase="Forbidden",
            headers={"Call-ID": call.sip_call_id})

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is False

    @pytest.mark.asyncio
    async def test_transfer_fails_on_timeout(self):
        """transfer_call returns False on timeout."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call

        mgr._sip_client.send_request.side_effect = TimeoutError("timed out")

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is False

    @pytest.mark.asyncio
    async def test_transfer_rejects_non_active_call(self):
        """transfer_call rejects calls not in ACTIVE or HELD state."""
        mgr = _make_manager()
        call = _make_call(state=VoLTECallState.RINGING_IN)
        mgr._calls[call.sip_call_id] = call

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is False

    @pytest.mark.asyncio
    async def test_transfer_works_for_held_call(self):
        """transfer_call works for calls in HELD state."""
        mgr = _make_manager()
        call = _make_call(state=VoLTECallState.HELD)
        mgr._calls[call.sip_call_id] = call

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=202, reason_phrase="Accepted",
            headers={"Call-ID": call.sip_call_id})

        result = await mgr.transfer_call(call.sip_call_id, "+5559999")
        assert result is True

    @pytest.mark.asyncio
    async def test_transfer_unknown_call_returns_false(self):
        """transfer_call returns False for unknown call ID."""
        mgr = _make_manager()
        result = await mgr.transfer_call("nonexistent", "+5559999")
        assert result is False


class TestIncomingRefer:
    """Test handling of incoming SIP REFER (transfer from remote)."""

    @pytest.mark.asyncio
    async def test_incoming_refer_sends_202_accepted(self):
        """Incoming REFER gets 202 Accepted response."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call
        mgr._radio_hal = MagicMock()
        mgr._radio_hal.dial = AsyncMock()
        mgr._radio_hal.voice_calls = []

        msg = SIPMessage(
            method="REFER",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "1 REFER",
                "Refer-To": "<sip:5559999@ims.example.com>",
            },
        )
        addr = ("10.0.0.1", 5060)

        # Mock hangup to avoid full teardown
        mgr.hangup_call = AsyncMock(return_value=True)
        # Mock _send_refer_notify to avoid SIP client interactions
        mgr._send_refer_notify = AsyncMock()

        await mgr._handle_incoming_refer(msg, addr)

        # Verify 202 Accepted was sent
        send_calls = mgr._sip_client.transport.send.call_args_list
        assert len(send_calls) >= 1
        response_msg = send_calls[0][0][0]
        assert response_msg.status_code == 202
        assert response_msg.reason_phrase == "Accepted"

    @pytest.mark.asyncio
    async def test_incoming_refer_dials_target(self):
        """Incoming REFER dials the Refer-To target."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call
        mgr._radio_hal = MagicMock()
        mgr._radio_hal.dial = AsyncMock()
        mgr._radio_hal.voice_calls = []

        msg = SIPMessage(
            method="REFER",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "1 REFER",
                "Refer-To": "<sip:5559999@ims.example.com>",
            },
        )

        mgr.hangup_call = AsyncMock(return_value=True)
        mgr._send_refer_notify = AsyncMock()

        await mgr._handle_incoming_refer(msg, ("10.0.0.1", 5060))

        mgr._radio_hal.dial.assert_called_once_with("5559999")

    @pytest.mark.asyncio
    async def test_incoming_refer_hangs_up_old_call(self):
        """Incoming REFER terminates the original call."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call
        mgr._radio_hal = MagicMock()
        mgr._radio_hal.dial = AsyncMock()
        mgr._radio_hal.voice_calls = []

        msg = SIPMessage(
            method="REFER",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "1 REFER",
                "Refer-To": "<sip:5559999@ims.example.com>",
            },
        )

        mgr.hangup_call = AsyncMock(return_value=True)
        mgr._send_refer_notify = AsyncMock()

        await mgr._handle_incoming_refer(msg, ("10.0.0.1", 5060))

        mgr.hangup_call.assert_called_once_with(call.sip_call_id)

    @pytest.mark.asyncio
    async def test_incoming_refer_sends_notify_trying_and_ok(self):
        """Incoming REFER sends NOTIFY 100 Trying then 200 OK."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call
        mgr._radio_hal = MagicMock()
        mgr._radio_hal.dial = AsyncMock()
        mgr._radio_hal.voice_calls = []

        msg = SIPMessage(
            method="REFER",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "1 REFER",
                "Refer-To": "<sip:5559999@ims.example.com>",
            },
        )

        mgr.hangup_call = AsyncMock(return_value=True)
        notify_calls = []
        original_send = mgr._send_refer_notify

        async def track_notify(call, addr, sipfrag, sub_state):
            notify_calls.append((sipfrag.strip(), sub_state))

        mgr._send_refer_notify = track_notify

        await mgr._handle_incoming_refer(msg, ("10.0.0.1", 5060))

        assert len(notify_calls) == 2
        assert "100 Trying" in notify_calls[0][0]
        assert notify_calls[0][1] == "active"
        assert "200 OK" in notify_calls[1][0]
        assert "terminated" in notify_calls[1][1]

    @pytest.mark.asyncio
    async def test_incoming_refer_unknown_call_ignored(self):
        """REFER for unknown call is silently ignored."""
        mgr = _make_manager()

        msg = SIPMessage(
            method="REFER",
            request_uri="sip:user@ims.example.com",
            headers={
                "Call-ID": "nonexistent",
                "CSeq": "1 REFER",
                "Refer-To": "<sip:5559999@ims.example.com>",
            },
        )

        # Should not raise
        await mgr._handle_incoming_refer(msg, ("10.0.0.1", 5060))


class TestNotifyHandling:
    """Test NOTIFY handling for REFER implicit subscription."""

    @pytest.mark.asyncio
    async def test_notify_200_terminates_transfer(self):
        """NOTIFY with sipfrag 200 OK hangs up the transferred call."""
        mgr = _make_manager()
        call = _make_call()
        call._transfer_pending = True
        mgr._calls[call.sip_call_id] = call

        mgr.hangup_call = AsyncMock(return_value=True)

        msg = SIPMessage(
            method="NOTIFY",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "2 NOTIFY",
                "Event": "refer",
                "Subscription-State": "terminated;reason=noresource",
                "Content-Type": "message/sipfrag;version=2.0",
            },
            body=b"SIP/2.0 200 OK\r\n",
        )

        await mgr._handle_incoming_notify(msg, ("10.0.0.1", 5060))

        mgr.hangup_call.assert_called_once_with(call.sip_call_id)

    @pytest.mark.asyncio
    async def test_notify_100_does_not_terminate(self):
        """NOTIFY with sipfrag 100 Trying does not hang up."""
        mgr = _make_manager()
        call = _make_call()
        call._transfer_pending = True
        mgr._calls[call.sip_call_id] = call

        mgr.hangup_call = AsyncMock(return_value=True)

        msg = SIPMessage(
            method="NOTIFY",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "2 NOTIFY",
                "Event": "refer",
                "Subscription-State": "active",
                "Content-Type": "message/sipfrag;version=2.0",
            },
            body=b"SIP/2.0 100 Trying\r\n",
        )

        await mgr._handle_incoming_notify(msg, ("10.0.0.1", 5060))

        mgr.hangup_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_notify_failure_clears_transfer(self):
        """NOTIFY with sipfrag 4xx clears transfer_pending."""
        mgr = _make_manager()
        call = _make_call()
        call._transfer_pending = True
        mgr._calls[call.sip_call_id] = call

        mgr.hangup_call = AsyncMock(return_value=True)

        msg = SIPMessage(
            method="NOTIFY",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:5551234@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "2 NOTIFY",
                "Event": "refer",
                "Subscription-State": "terminated;reason=rejected",
                "Content-Type": "message/sipfrag;version=2.0",
            },
            body=b"SIP/2.0 486 Busy Here\r\n",
        )

        await mgr._handle_incoming_notify(msg, ("10.0.0.1", 5060))

        # Should NOT hang up — transfer failed
        mgr.hangup_call.assert_not_called()
        assert not hasattr(call, "_transfer_pending")

    @pytest.mark.asyncio
    async def test_notify_sends_200_ok_response(self):
        """NOTIFY always receives a 200 OK response."""
        mgr = _make_manager()
        call = _make_call()
        mgr._calls[call.sip_call_id] = call

        msg = SIPMessage(
            method="NOTIFY",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:remote@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "2 NOTIFY",
                "Event": "refer",
                "Subscription-State": "active",
            },
            body=b"SIP/2.0 100 Trying\r\n",
        )

        await mgr._handle_incoming_notify(msg, ("10.0.0.1", 5060))

        send_calls = mgr._sip_client.transport.send.call_args_list
        assert len(send_calls) == 1
        response_msg = send_calls[0][0][0]
        assert response_msg.status_code == 200

    @pytest.mark.asyncio
    async def test_notify_non_refer_event_ignored(self):
        """NOTIFY with Event != refer is acknowledged but not processed."""
        mgr = _make_manager()
        call = _make_call()
        call._transfer_pending = True
        mgr._calls[call.sip_call_id] = call

        mgr.hangup_call = AsyncMock(return_value=True)

        msg = SIPMessage(
            method="NOTIFY",
            request_uri="sip:user@ims.example.com",
            headers={
                "Via": "SIP/2.0/UDP 10.0.0.1",
                "From": "<sip:remote@ims.example.com>;tag=abc",
                "To": "<sip:user@ims.example.com>;tag=xyz",
                "Call-ID": call.sip_call_id,
                "CSeq": "2 NOTIFY",
                "Event": "presence",
                "Subscription-State": "terminated",
            },
            body=b"SIP/2.0 200 OK\r\n",
        )

        await mgr._handle_incoming_notify(msg, ("10.0.0.1", 5060))

        # Should not hang up (wrong event type)
        mgr.hangup_call.assert_not_called()


class TestAttendedTransfer:
    """Test attended (consultative) call transfer."""

    @pytest.mark.asyncio
    async def test_attended_transfer_sends_refer_with_replaces(self):
        """attended_transfer sends REFER with Replaces header."""
        mgr = _make_manager()
        call_a = _make_call(call_id="call-a", remote_uri="sip:alice@ims.example.com")
        call_b = _make_call(call_id="call-b", remote_uri="sip:bob@ims.example.com")
        mgr._calls["call-a"] = call_a
        mgr._calls["call-b"] = call_b

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=202, reason_phrase="Accepted",
            headers={"Call-ID": "call-a"})

        result = await mgr.attended_transfer("call-a", "call-b")
        assert result is True

        send_call = mgr._sip_client.send_request.call_args
        assert send_call.kwargs["method"] == "REFER"
        headers = send_call.kwargs["extra_headers"]
        assert "Replaces=call-b" in headers["Refer-To"]
        assert "bob@ims.example.com" in headers["Refer-To"]

    @pytest.mark.asyncio
    async def test_attended_transfer_fails_missing_call(self):
        """attended_transfer fails if either call doesn't exist."""
        mgr = _make_manager()
        call_a = _make_call(call_id="call-a")
        mgr._calls["call-a"] = call_a

        result = await mgr.attended_transfer("call-a", "call-missing")
        assert result is False

    @pytest.mark.asyncio
    async def test_attended_transfer_fails_non_active_call(self):
        """attended_transfer fails if call A is not active/held."""
        mgr = _make_manager()
        call_a = _make_call(call_id="call-a", state=VoLTECallState.RINGING_IN)
        call_b = _make_call(call_id="call-b")
        mgr._calls["call-a"] = call_a
        mgr._calls["call-b"] = call_b

        result = await mgr.attended_transfer("call-a", "call-b")
        assert result is False

    @pytest.mark.asyncio
    async def test_attended_transfer_rejected(self):
        """attended_transfer returns False on rejection."""
        mgr = _make_manager()
        call_a = _make_call(call_id="call-a")
        call_b = _make_call(call_id="call-b")
        mgr._calls["call-a"] = call_a
        mgr._calls["call-b"] = call_b

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=603, reason_phrase="Decline",
            headers={"Call-ID": "call-a"})

        result = await mgr.attended_transfer("call-a", "call-b")
        assert result is False

    @pytest.mark.asyncio
    async def test_attended_transfer_sets_pending(self):
        """attended_transfer sets _transfer_pending on call A."""
        mgr = _make_manager()
        call_a = _make_call(call_id="call-a")
        call_b = _make_call(call_id="call-b")
        mgr._calls["call-a"] = call_a
        mgr._calls["call-b"] = call_b

        mgr._sip_client.send_request.return_value = SIPMessage(
            status_code=202, reason_phrase="Accepted",
            headers={"Call-ID": "call-a"})

        await mgr.attended_transfer("call-a", "call-b")
        assert getattr(call_a, "_transfer_pending", False) is True


class TestSendReferNotify:
    """Test _send_refer_notify helper."""

    @pytest.mark.asyncio
    async def test_sends_notify_with_sipfrag(self):
        """_send_refer_notify sends NOTIFY with correct headers and body."""
        mgr = _make_manager()
        call = _make_call()

        await mgr._send_refer_notify(
            call, ("10.0.0.1", 5060),
            "SIP/2.0 200 OK\r\n", "terminated;reason=noresource")

        send_call = mgr._sip_client.send_request.call_args
        assert send_call.kwargs["method"] == "NOTIFY"
        headers = send_call.kwargs["extra_headers"]
        assert headers["Event"] == "refer"
        assert "terminated" in headers["Subscription-State"]
        assert headers["Content-Type"] == "message/sipfrag;version=2.0"
        assert send_call.kwargs["body"] == b"SIP/2.0 200 OK\r\n"

    @pytest.mark.asyncio
    async def test_sends_notify_active_state(self):
        """_send_refer_notify can send with active subscription state."""
        mgr = _make_manager()
        call = _make_call()

        await mgr._send_refer_notify(
            call, ("10.0.0.1", 5060),
            "SIP/2.0 100 Trying\r\n", "active")

        send_call = mgr._sip_client.send_request.call_args
        headers = send_call.kwargs["extra_headers"]
        assert headers["Subscription-State"] == "active"

    @pytest.mark.asyncio
    async def test_no_crash_without_sip_client(self):
        """_send_refer_notify is a no-op if SIP client is None."""
        mgr = _make_manager()
        mgr._sip_client = None
        call = _make_call()

        # Should not raise
        await mgr._send_refer_notify(
            call, ("10.0.0.1", 5060), "SIP/2.0 200 OK\r\n", "terminated")


class TestIncomingSipRouting:
    """Test that NOTIFY and REFER are routed properly in _handle_incoming_sip."""

    @pytest.mark.asyncio
    async def test_refer_routed_to_handler(self):
        """REFER request is routed to _handle_incoming_refer."""
        mgr = _make_manager()
        mgr._handle_incoming_refer = AsyncMock()

        msg = SIPMessage(
            method="REFER",
            request_uri="sip:user@ims.example.com",
            headers={"Call-ID": "test-call", "CSeq": "1 REFER"},
        )

        await mgr._handle_incoming_sip(msg, ("10.0.0.1", 5060))
        mgr._handle_incoming_refer.assert_called_once()

    @pytest.mark.asyncio
    async def test_notify_routed_to_handler(self):
        """NOTIFY request is routed to _handle_incoming_notify."""
        mgr = _make_manager()
        mgr._handle_incoming_notify = AsyncMock()

        msg = SIPMessage(
            method="NOTIFY",
            request_uri="sip:user@ims.example.com",
            headers={"Call-ID": "test-call", "CSeq": "1 NOTIFY",
                      "Event": "refer"},
        )

        await mgr._handle_incoming_sip(msg, ("10.0.0.1", 5060))
        mgr._handle_incoming_notify.assert_called_once()
