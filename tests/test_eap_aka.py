"""Tests for the EAP-AKA implementation."""

import pytest

from euicc.crypto.eap_aka import (
    EAPAKASession,
    EAPPacket,
    EAPCode,
    EAPType,
    AKASubtype,
    ATType,
)
from euicc.crypto.milenage import Milenage


class TestEAPPacket:
    def test_parse_request(self):
        """Test parsing an EAP-Request."""
        # Minimal EAP-Request/AKA-Challenge
        data = bytes([
            0x01,  # Code: Request
            0x01,  # Identifier
            0x00, 0x08,  # Length
            0x17,  # Type: AKA (23)
            0x01,  # Subtype: Challenge
            0x00, 0x00,  # Reserved
        ])
        pkt = EAPPacket.parse(data)
        assert pkt.code == EAPCode.REQUEST
        assert pkt.identifier == 1
        assert pkt.eap_type == EAPType.AKA
        assert pkt.subtype == AKASubtype.CHALLENGE

    def test_serialize_response(self):
        """Test serializing an EAP-Response."""
        pkt = EAPPacket(
            code=EAPCode.RESPONSE,
            identifier=42,
            eap_type=EAPType.AKA,
            subtype=AKASubtype.CHALLENGE,
            attributes={},
        )
        data = pkt.serialize()
        assert data[0] == EAPCode.RESPONSE
        assert data[1] == 42
        assert data[4] == EAPType.AKA

    def test_success_packet(self):
        pkt = EAPPacket(code=EAPCode.SUCCESS, identifier=5)
        data = pkt.serialize()
        assert len(data) == 4
        assert data[0] == EAPCode.SUCCESS

    def test_failure_packet(self):
        pkt = EAPPacket(code=EAPCode.FAILURE, identifier=5)
        data = pkt.serialize()
        assert len(data) == 4
        assert data[0] == EAPCode.FAILURE


class TestEAPAKASession:
    KI = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
    OPC = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
    IMSI = "001010123456789"

    @pytest.fixture
    def session(self):
        return EAPAKASession(
            ki=self.KI,
            opc=self.OPC,
            imsi=self.IMSI,
            sqn=0,
        )

    def test_process_challenge(self, session):
        """Test processing a valid AKA challenge."""
        rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
        sqn = bytes.fromhex("ff9bb4d0b607")
        amf = bytes.fromhex("b9b9")

        # Generate valid AUTN
        mil = Milenage(self.KI, self.OPC)
        _, _, _, ak = mil.f2345(rand)
        sqn_ak = Milenage._xor(sqn, ak)
        mac_a = mil.f1(rand, sqn, amf)
        autn = sqn_ak + amf + mac_a

        # Build EAP-Request/AKA-Challenge
        challenge = EAPPacket(
            code=EAPCode.REQUEST,
            identifier=1,
            eap_type=EAPType.AKA,
            subtype=AKASubtype.CHALLENGE,
            attributes={
                ATType.AT_RAND: rand,
                ATType.AT_AUTN: autn,
                ATType.AT_MAC: b"\x00" * 16,
            },
        )

        response = session.process_challenge(challenge)

        assert response.code == EAPCode.RESPONSE
        assert response.subtype == AKASubtype.CHALLENGE
        assert ATType.AT_RES in response.attributes
        assert ATType.AT_MAC in response.attributes

        # Verify RES is correct
        res_attr = response.attributes[ATType.AT_RES]
        # First 2 bytes are RES length in bits
        import struct
        res_bits = struct.unpack("!H", res_attr[:2])[0]
        assert res_bits == 64  # 8 bytes * 8 bits

    def test_sync_failure(self, session):
        """Test that sync failure produces AUTS."""
        rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
        # Use an AUTN with wrong MAC to trigger sync failure
        autn = bytes(16)

        challenge = EAPPacket(
            code=EAPCode.REQUEST,
            identifier=1,
            eap_type=EAPType.AKA,
            subtype=AKASubtype.CHALLENGE,
            attributes={
                ATType.AT_RAND: rand,
                ATType.AT_AUTN: autn,
            },
        )

        response = session.process_challenge(challenge)
        assert response.subtype == AKASubtype.SYNCHRONIZATION_FAILURE
        assert ATType.AT_AUTS in response.attributes

    def test_key_derivation(self, session):
        """Test that keys are derived after successful challenge."""
        rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
        sqn = bytes.fromhex("ff9bb4d0b607")
        amf = bytes.fromhex("b9b9")

        mil = Milenage(self.KI, self.OPC)
        _, _, _, ak = mil.f2345(rand)
        sqn_ak = Milenage._xor(sqn, ak)
        mac_a = mil.f1(rand, sqn, amf)
        autn = sqn_ak + amf + mac_a

        challenge = EAPPacket(
            code=EAPCode.REQUEST,
            identifier=1,
            eap_type=EAPType.AKA,
            subtype=AKASubtype.CHALLENGE,
            attributes={
                ATType.AT_RAND: rand,
                ATType.AT_AUTN: autn,
            },
        )

        session.process_challenge(challenge)

        assert session.mk is not None
        assert session.k_aut is not None
        assert session.k_encr is not None
        assert session.msk is not None
        assert len(session.k_aut) == 16
        assert len(session.k_encr) == 16
        assert len(session.msk) == 64


class TestEAPAKAPrimeSession:
    """Test EAP-AKA' variant."""

    KI = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
    OPC = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
    IMSI = "001010123456789"

    def test_aka_prime_key_derivation(self):
        """Test that EAP-AKA' derives different keys than EAP-AKA."""
        rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
        sqn = bytes.fromhex("ff9bb4d0b607")
        amf = bytes.fromhex("b9b9")

        mil = Milenage(self.KI, self.OPC)
        _, _, _, ak = mil.f2345(rand)
        sqn_ak = Milenage._xor(sqn, ak)
        mac_a = mil.f1(rand, sqn, amf)
        autn = sqn_ak + amf + mac_a

        # EAP-AKA
        session_aka = EAPAKASession(
            ki=self.KI, opc=self.OPC, imsi=self.IMSI,
            use_aka_prime=False,
        )
        # EAP-AKA'
        session_prime = EAPAKASession(
            ki=self.KI, opc=self.OPC, imsi=self.IMSI,
            use_aka_prime=True, network_name="WLAN",
        )

        challenge = EAPPacket(
            code=EAPCode.REQUEST,
            identifier=1,
            eap_type=EAPType.AKA,
            subtype=AKASubtype.CHALLENGE,
            attributes={ATType.AT_RAND: rand, ATType.AT_AUTN: autn},
        )

        session_aka.process_challenge(challenge)

        challenge_prime = EAPPacket(
            code=EAPCode.REQUEST,
            identifier=1,
            eap_type=EAPType.AKA_PRIME,
            subtype=AKASubtype.CHALLENGE,
            attributes={ATType.AT_RAND: rand, ATType.AT_AUTN: autn},
        )
        session_prime.process_challenge(challenge_prime)

        # AKA' should derive different keys than AKA
        assert session_aka.mk != session_prime.mk
        assert session_aka.k_aut != session_prime.k_aut
