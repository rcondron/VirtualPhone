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
