"""Tests for IMS components."""

import pytest

from ims.sip_client import (
    SIPMessage,
    SIPClient,
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
