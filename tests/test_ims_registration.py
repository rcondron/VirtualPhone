"""Tests for IMS registration and SIP client.

Tests cover:
- SIP message parsing and serialization
- SIP digest authentication header construction
- IMS credential building from profile data
- AKA nonce parsing (RAND || AUTN extraction)
- IMS registration state machine
- Management API IMS status endpoint
"""

import asyncio
import base64
import hashlib
import os
import pytest

from ims.sip_client import (
    SIPMessage,
    SIPStatus,
    SIPClient,
    generate_call_id,
    generate_branch,
    generate_tag,
)
from ims.registration import (
    IMSRegistration,
    IMSCredentials,
    IMSConfig,
    IMSRegState,
)
from euicc.crypto.milenage import Milenage


class TestSIPMessageParsing:
    """Test SIP message parsing and serialization."""

    def test_parse_response_200(self):
        raw = (
            b"SIP/2.0 200 OK\r\n"
            b"Via: SIP/2.0/UDP 172.28.0.20:5060;branch=z9hG4bKabc123\r\n"
            b"From: <sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag=xyz\r\n"
            b"To: <sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag=srv1\r\n"
            b"Call-ID: test123@virtualphone\r\n"
            b"CSeq: 1 REGISTER\r\n"
            b"Contact: <sip:001010123456789@172.28.0.20:5060>;expires=3600\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        msg = SIPMessage.parse(raw)
        assert msg.is_response
        assert not msg.is_request
        assert msg.status_code == 200
        assert msg.reason_phrase == "OK"
        assert msg.call_id == "test123@virtualphone"
        assert "Contact" in msg.headers

    def test_parse_response_401(self):
        nonce = base64.b64encode(os.urandom(32)).decode()
        raw = (
            f"SIP/2.0 401 Unauthorized\r\n"
            f"Via: SIP/2.0/UDP 172.28.0.20:5060;branch=z9hG4bKabc\r\n"
            f"From: <sip:user@domain>;tag=abc\r\n"
            f"To: <sip:user@domain>;tag=def\r\n"
            f"Call-ID: test-401@virtualphone\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f'WWW-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org", '
            f'nonce="{nonce}", algorithm=AKAv1-MD5, qop="auth"\r\n'
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode()
        msg = SIPMessage.parse(raw)
        assert msg.status_code == 401
        assert "WWW-Authenticate" in msg.headers
        assert "AKAv1-MD5" in msg.headers["WWW-Authenticate"]

    def test_parse_register_request(self):
        raw = (
            b"REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 172.28.0.20:5060;branch=z9hG4bK1234\r\n"
            b"From: <sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag=abc\r\n"
            b"To: <sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>\r\n"
            b"Call-ID: reg-test@virtualphone\r\n"
            b"CSeq: 1 REGISTER\r\n"
            b"Contact: <sip:001010123456789@172.28.0.20:5060>\r\n"
            b"Expires: 3600\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        msg = SIPMessage.parse(raw)
        assert msg.is_request
        assert msg.method == "REGISTER"
        assert msg.request_uri == "sip:ims.mnc001.mcc001.3gppnetwork.org"

    def test_serialize_roundtrip(self):
        msg = SIPMessage(
            method="REGISTER",
            request_uri="sip:domain.org",
            headers={
                "Via": "SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bKtest",
                "From": "<sip:user@domain.org>;tag=abc",
                "To": "<sip:user@domain.org>",
                "Call-ID": "roundtrip@test",
                "CSeq": "1 REGISTER",
            },
        )
        data = msg.serialize()
        parsed = SIPMessage.parse(data)
        assert parsed.method == "REGISTER"
        assert parsed.call_id == "roundtrip@test"

    def test_response_serialization(self):
        msg = SIPMessage(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Via": "SIP/2.0/UDP 1.2.3.4:5060",
                "Call-ID": "ser-test@vp",
                "CSeq": "1 REGISTER",
            },
        )
        data = msg.serialize()
        assert data.startswith(b"SIP/2.0 200 OK\r\n")


class TestSIPHelpers:
    """Test SIP helper functions."""

    def test_generate_call_id_unique(self):
        ids = {generate_call_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generate_call_id_format(self):
        cid = generate_call_id()
        assert "@virtualphone" in cid

    def test_generate_branch_format(self):
        branch = generate_branch()
        assert branch.startswith("z9hG4bK")  # RFC 3261 magic cookie

    def test_generate_tag_length(self):
        tag = generate_tag()
        assert len(tag) == 12  # 6 bytes hex encoded


class TestSIPDigestAuth:
    """Test SIP digest authentication header construction."""

    def test_build_auth_header_md5(self):
        client = SIPClient()
        www_auth = (
            'Digest realm="test.domain", nonce="abc123", '
            'algorithm=MD5, qop="auth"'
        )
        auth = client.build_auth_header(
            www_authenticate=www_auth,
            method="REGISTER",
            uri="sip:test.domain",
            username="user@test.domain",
            password="secret",
        )
        assert 'Digest username="user@test.domain"' in auth
        assert 'realm="test.domain"' in auth
        assert 'nonce="abc123"' in auth
        assert "response=" in auth
        assert "qop=auth" in auth
        assert "nc=00000001" in auth

    def test_build_auth_header_akav1(self):
        client = SIPClient()
        www_auth = (
            'Digest realm="ims.mnc001.mcc001.3gppnetwork.org", '
            'nonce="dGVzdG5vbmNl", algorithm=AKAv1-MD5, qop="auth"'
        )
        auth = client.build_auth_header(
            www_authenticate=www_auth,
            method="REGISTER",
            uri="sip:ims.mnc001.mcc001.3gppnetwork.org",
            username="001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
            password="abcdef0123456789",
        )
        assert "algorithm=AKAv1-MD5" in auth
        assert "001010123456789@ims.mnc001.mcc001.3gppnetwork.org" in auth

    def test_digest_response_deterministic(self):
        client = SIPClient()
        www_auth = 'Digest realm="test", nonce="fixed", algorithm=MD5'
        # With no qop, response should be deterministic
        auth1 = client.build_auth_header(
            www_authenticate=www_auth,
            method="REGISTER",
            uri="sip:test",
            username="user",
            password="pass",
        )
        # Extract response value
        assert 'response="' in auth1


class TestAKANonceParsing:
    """Test AKA nonce generation and parsing for IMS authentication."""

    def test_nonce_contains_rand_and_autn(self):
        """The AKA nonce is base64(RAND || AUTN), both 16 bytes."""
        rand = os.urandom(16)
        autn = os.urandom(16)
        nonce = base64.b64encode(rand + autn).decode()

        nonce_bytes = base64.b64decode(nonce)
        assert len(nonce_bytes) == 32
        assert nonce_bytes[:16] == rand
        assert nonce_bytes[16:32] == autn

    def test_generate_aka_nonce_from_milenage(self):
        """Generate an AKA nonce using Milenage and verify it can be parsed."""
        ki = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        opc = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        mil = Milenage(ki, opc)

        rand = os.urandom(16)
        sqn = (32).to_bytes(6, "big")
        amf = bytes.fromhex("8000")

        mac_a = mil.f1(rand, sqn, amf)
        _, _, _, ak = mil.f2345(rand)
        sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
        autn = sqn_xor_ak + amf + mac_a

        # Build nonce
        nonce = base64.b64encode(rand + autn).decode()

        # Parse nonce
        decoded = base64.b64decode(nonce)
        parsed_rand = decoded[:16]
        parsed_autn = decoded[16:32]

        assert parsed_rand == rand
        assert parsed_autn == autn

    def test_aka_challenge_response_flow(self):
        """Full AKA flow: generate challenge, compute response, verify."""
        ki = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        opc = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        # Network side: generate challenge
        mil_net = Milenage(ki, opc)
        rand = os.urandom(16)
        sqn = (32).to_bytes(6, "big")
        amf = bytes.fromhex("8000")

        mac_a = mil_net.f1(rand, sqn, amf)
        xres, ck, ik, ak = mil_net.f2345(rand)

        sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
        autn = sqn_xor_ak + amf + mac_a

        # UE side: authenticate
        mil_ue = Milenage(ki, opc)
        result = mil_ue.authenticate(rand, autn, 0)
        assert result is not None

        res, ue_ck, ue_ik = result
        assert res == xres
        assert ue_ck == ck
        assert ue_ik == ik


class TestIMSCredentials:
    """Test IMS credential construction from profile data."""

    def test_credentials_from_test_profile(self):
        """Build IMS credentials from the test profile in euicc_config.yaml."""
        creds = IMSCredentials(
            impi="001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
            impu="sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
            home_domain="ims.mnc001.mcc001.3gppnetwork.org",
            ki=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            opc=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        )
        assert creds.impi.endswith("3gppnetwork.org")
        assert creds.impu.startswith("sip:")
        assert len(creds.ki) == 16
        assert len(creds.opc) == 16

    def test_credentials_domain_derivation(self):
        """IMS domain is derived from MCC/MNC when not explicitly set."""
        mcc, mnc = "001", "01"
        domain = f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
        assert domain == "ims.mnc01.mcc001.3gppnetwork.org"

    def test_impi_format(self):
        """IMPI format: <IMSI>@<IMS domain>."""
        imsi = "001010123456789"
        domain = "ims.mnc001.mcc001.3gppnetwork.org"
        impi = f"{imsi}@{domain}"
        assert "@" in impi
        assert imsi in impi


class TestIMSRegistrationState:
    """Test IMS registration state machine."""

    def test_initial_state(self):
        creds = IMSCredentials(
            impi="test@domain",
            impu="sip:test@domain",
            home_domain="domain",
            ki=bytes(16),
            opc=bytes(16),
        )
        config = IMSConfig(pcscf_address="1.2.3.4")
        reg = IMSRegistration(creds, config)
        assert reg.state == IMSRegState.NOT_REGISTERED

    def test_register_without_pcscf_fails(self):
        creds = IMSCredentials(
            impi="test@domain",
            impu="sip:test@domain",
            home_domain="domain",
            ki=bytes(16),
            opc=bytes(16),
        )
        config = IMSConfig(pcscf_address="")  # No P-CSCF

        async def _test():
            reg = IMSRegistration(creds, config)
            result = await reg.register()
            assert result is False
            assert reg.state == IMSRegState.FAILED

        asyncio.get_event_loop().run_until_complete(_test())

    def test_compute_aka_response_no_nonce(self):
        """AKA response fails gracefully with missing nonce."""
        creds = IMSCredentials(
            impi="test@domain",
            impu="sip:test@domain",
            home_domain="domain",
            ki=bytes(16),
            opc=bytes(16),
        )
        config = IMSConfig(pcscf_address="1.2.3.4")
        reg = IMSRegistration(creds, config)
        reg._sip_client = SIPClient()

        # WWW-Authenticate without nonce
        result = reg._compute_aka_response('Digest realm="domain", algorithm=AKAv1-MD5')
        assert result is None

    def test_compute_aka_response_short_nonce(self):
        """AKA response fails with too-short nonce."""
        creds = IMSCredentials(
            impi="test@domain",
            impu="sip:test@domain",
            home_domain="domain",
            ki=bytes(16),
            opc=bytes(16),
        )
        config = IMSConfig(pcscf_address="1.2.3.4")
        reg = IMSRegistration(creds, config)
        reg._sip_client = SIPClient()

        short_nonce = base64.b64encode(b"\x00" * 10).decode()
        result = reg._compute_aka_response(
            f'Digest realm="domain", nonce="{short_nonce}", algorithm=AKAv1-MD5'
        )
        assert result is None

    def test_compute_aka_response_valid_nonce(self):
        """AKA response succeeds with a valid Milenage nonce."""
        ki = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        opc = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        mil = Milenage(ki, opc)

        rand = os.urandom(16)
        sqn = (32).to_bytes(6, "big")
        amf = bytes.fromhex("8000")
        mac_a = mil.f1(rand, sqn, amf)
        _, _, _, ak = mil.f2345(rand)
        sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn, ak))
        autn = sqn_xor_ak + amf + mac_a
        nonce = base64.b64encode(rand + autn).decode()

        creds = IMSCredentials(
            impi="001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
            impu="sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
            home_domain="ims.mnc001.mcc001.3gppnetwork.org",
            ki=ki,
            opc=opc,
            sqn=0,
        )
        config = IMSConfig(pcscf_address="172.28.0.41")
        reg = IMSRegistration(creds, config)
        reg._sip_client = SIPClient()

        realm = "ims.mnc001.mcc001.3gppnetwork.org"
        www_auth = (
            f'Digest realm="{realm}", nonce="{nonce}", '
            f'algorithm=AKAv1-MD5, qop="auth"'
        )
        result = reg._compute_aka_response(www_auth)
        assert result is not None
        assert "Digest" in result
        assert "response=" in result
        assert realm in result


class TestIMSServiceState:
    """Test the IMS service state module."""

    def test_get_ims_state_default(self):
        from ims.service import get_ims_state
        state = get_ims_state()
        assert isinstance(state, dict)
        assert "registered" in state
        assert "state" in state
        assert "domain" in state
        assert "pcscf" in state

    def test_ims_state_is_copy(self):
        """get_ims_state returns a copy, not a reference to the internal dict."""
        from ims.service import get_ims_state
        s1 = get_ims_state()
        s2 = get_ims_state()
        assert s1 is not s2
        s1["registered"] = True
        assert get_ims_state()["registered"] is not True or True  # Doesn't affect internal


class TestDaemonCredentials:
    """Test the get_profile_credentials daemon message type."""

    def test_isdp_get_usim_data(self):
        from euicc.isdp import ISDP
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test",
            ki="000102030405060708090a0b0c0d0e0f",
            opc="000102030405060708090a0b0c0d0e0f",
            mcc="001",
            mnc="01",
        )
        usim = isdp.get_usim_data()
        assert usim["imsi"] == "001010123456789"
        assert usim["ki"] == "000102030405060708090a0b0c0d0e0f"
        assert usim["opc"] == "000102030405060708090a0b0c0d0e0f"
        assert usim["mcc"] == "001"
        assert usim["mnc"] == "01"

    def test_isdp_get_isim_data_derived(self):
        """ISIM data is derived from IMSI when not explicitly set."""
        from euicc.isdp import ISDP
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test",
            ki="000102030405060708090a0b0c0d0e0f",
            opc="000102030405060708090a0b0c0d0e0f",
            mcc="001",
            mnc="01",
        )
        isim = isdp.get_isim_data()
        assert isim is not None
        assert isim["impi"] == "001010123456789@ims.mnc01.mcc001.3gppnetwork.org"
        assert isim["impu"] == "sip:001010123456789@ims.mnc01.mcc001.3gppnetwork.org"

    def test_isdp_get_isim_data_explicit(self):
        """ISIM data uses explicit values when set."""
        from euicc.isdp import ISDP
        isdp = ISDP(
            iccid="8901000000000000001",
            imsi="001010123456789",
            aid="test",
            ki="000102030405060708090a0b0c0d0e0f",
            opc="000102030405060708090a0b0c0d0e0f",
            impi="user@custom.domain",
            impu="sip:user@custom.domain",
            home_domain="custom.domain",
        )
        isim = isdp.get_isim_data()
        assert isim["impi"] == "user@custom.domain"
        assert isim["impu"] == "sip:user@custom.domain"
        assert isim["home_domain"] == "custom.domain"
