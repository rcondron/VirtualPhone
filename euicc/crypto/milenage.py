"""
Milenage algorithm implementation (3GPP TS 35.206).

Milenage is the standard algorithm set for USIM authentication in 3G/4G/5G
networks. It produces:
- RES  (response, used for mutual authentication)
- CK   (cipher key)
- IK   (integrity key)
- AK   (anonymity key)
- MACA (MAC-A for network authentication)
- MACS (MAC-S for resynchronization)

The algorithm is based on AES-128 (Rijndael) with the operator key Ki
and operator variant algorithm configuration field OPc.

This implementation is used by EAP-AKA and the AUTHENTICATE APDU command.
"""

from __future__ import annotations

import struct
from typing import Optional

from Crypto.Cipher import AES


class Milenage:
    """
    Milenage algorithm suite.

    Args:
        ki: 128-bit subscriber key (K).
        opc: 128-bit operator variant key (OPc), pre-computed from OP and Ki.
    """

    # Constants c1..c5 and r1..r5 per 3GPP TS 35.206 Section 4
    _C = [
        bytes(16),                                         # c1
        bytes.fromhex("00000000000000000000000000000001"),  # c2
        bytes.fromhex("00000000000000000000000000000002"),  # c3
        bytes.fromhex("00000000000000000000000000000004"),  # c4
        bytes.fromhex("00000000000000000000000000000008"),  # c5
    ]
    _R = [64, 0, 32, 64, 96]  # r1, r2, r3, r4, r5

    def __init__(self, ki: bytes, opc: bytes):
        if len(ki) != 16:
            raise ValueError("Ki must be 16 bytes")
        if len(opc) != 16:
            raise ValueError("OPc must be 16 bytes")
        self.ki = ki
        self.opc = opc

    @classmethod
    def compute_opc(cls, ki: bytes, op: bytes) -> bytes:
        """Compute OPc from OP and Ki: OPc = OP XOR E_K(OP)."""
        cipher = AES.new(ki, AES.MODE_ECB)
        enc = cipher.encrypt(op)
        return cls._xor(op, enc)

    def _encrypt(self, data: bytes) -> bytes:
        """AES-128-ECB encrypt."""
        cipher = AES.new(self.ki, AES.MODE_ECB)
        return cipher.encrypt(data)

    @staticmethod
    def _xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def _rotate(data: bytes, bits: int) -> bytes:
        """Rotate a 128-bit block left by `bits` positions."""
        if bits == 0:
            return data
        byte_shift = bits // 8
        bit_shift = bits % 8
        n = len(data)
        result = bytearray(n)
        for i in range(n):
            src1 = (i + byte_shift) % n
            src2 = (i + byte_shift + 1) % n
            result[i] = ((data[src1] << bit_shift) | (data[src2] >> (8 - bit_shift))) & 0xFF
        return bytes(result)

    def _f1_core(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """
        Core of f1/f1* — compute OUT1 (16 bytes).

        Per 3GPP TS 35.206 Annex 3 reference C code:
        OUT1 = E_K(TEMP XOR rotate(IN1 XOR OPc, r1) XOR c1) XOR OPc
        """
        # TEMP = E_K(RAND XOR OPc)
        temp = self._encrypt(self._xor(rand, self.opc))

        # IN1 = SQN || AMF || SQN || AMF
        in1 = sqn + amf + sqn + amf

        # rotate(IN1 XOR OPc, r1) — rotate the IN1/OPc mix, NOT temp/OPc
        rotated = self._rotate(self._xor(in1, self.opc), self._R[0])

        # XOR with TEMP and constant c1
        enc_input = self._xor(self._xor(temp, rotated), self._C[0])
        out = self._encrypt(enc_input)
        return self._xor(out, self.opc)

    def f1(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """f1 - Network authentication function. Returns MAC-A (8 bytes)."""
        return self._f1_core(rand, sqn, amf)[0:8]

    def f1star(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """f1* - Resynchronisation MAC function. Returns MAC-S (8 bytes)."""
        return self._f1_core(rand, sqn, amf)[8:16]

    def f2345(self, rand: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        """
        f2, f3, f4, f5 - Auth response, cipher/integrity key, anonymity key.

        Returns: (RES, CK, IK, AK) - (8, 16, 16, 6 bytes)
        """
        temp = self._encrypt(self._xor(rand, self.opc))

        # f2 (RES) and f5 (AK)
        out2 = self._encrypt(
            self._xor(self._rotate(self._xor(temp, self.opc), self._R[1]), self._C[1])
        )
        out2 = self._xor(out2, self.opc)
        res = out2[8:16]   # f2: RES (8 bytes)
        ak = out2[0:6]     # f5: AK (6 bytes)

        # f3 (CK)
        out3 = self._encrypt(
            self._xor(self._rotate(self._xor(temp, self.opc), self._R[2]), self._C[2])
        )
        ck = self._xor(out3, self.opc)

        # f4 (IK)
        out4 = self._encrypt(
            self._xor(self._rotate(self._xor(temp, self.opc), self._R[3]), self._C[3])
        )
        ik = self._xor(out4, self.opc)

        return res, ck, ik, ak

    def f5star(self, rand: bytes) -> bytes:
        """f5* - Resynchronisation anonymity key. Returns AK (6 bytes)."""
        temp = self._encrypt(self._xor(rand, self.opc))
        out = self._encrypt(
            self._xor(self._rotate(self._xor(temp, self.opc), self._R[4]), self._C[4])
        )
        result = self._xor(out, self.opc)
        return result[0:6]

    def authenticate(
        self, rand: bytes, autn: bytes, sqn_stored: int
    ) -> Optional[tuple[bytes, bytes, bytes]]:
        """
        Perform full USIM AKA authentication.

        Args:
            rand: 16-byte random challenge from network.
            autn: 16-byte authentication token from network (SQN^AK || AMF || MAC-A).
            sqn_stored: Current stored sequence number.

        Returns:
            (RES, CK, IK) on success, or None if MAC verification fails
            (indicating sync failure).
        """
        if len(rand) != 16 or len(autn) != 16:
            raise ValueError("RAND and AUTN must be 16 bytes")

        # Compute f2..f5
        res, ck, ik, ak = self.f2345(rand)

        # Recover SQN from AUTN: SQN = (SQN^AK) XOR AK
        sqn_ak = autn[0:6]
        amf = autn[6:8]
        mac_a_received = autn[8:16]

        sqn = self._xor(sqn_ak, ak)

        # Verify MAC-A
        mac_a_computed = self.f1(rand, sqn, amf)
        if mac_a_computed != mac_a_received:
            return None  # MAC failure -> sync required

        # Verify SQN is in acceptable range
        sqn_int = int.from_bytes(sqn, "big")
        if sqn_int < sqn_stored:
            return None  # SQN out of range -> resync

        return res, ck, ik

    def generate_auts(self, rand: bytes, sqn_stored: int) -> bytes:
        """
        Generate AUTS for resynchronization (3GPP TS 33.102).

        Returns: 14-byte AUTS = (SQN_MS XOR AK*) || MAC-S
        """
        sqn_bytes = sqn_stored.to_bytes(6, "big")
        ak_star = self.f5star(rand)
        concealed_sqn = self._xor(sqn_bytes, ak_star)
        amf = bytes(2)  # AMF is zero for resync
        mac_s = self.f1star(rand, sqn_bytes, amf)
        return concealed_sqn + mac_s

    def gsm_authenticate(self, rand: bytes) -> tuple[bytes, bytes]:
        """
        GSM (2G) authentication compatibility.

        Returns: (SRES, Kc) - (4, 8 bytes)
        """
        res, ck, ik, _ = self.f2345(rand)
        # SRES = first 4 bytes of RES
        sres = res[:4]
        # Kc = CK[0:8] XOR CK[8:16] XOR IK[0:8] XOR IK[8:16]
        kc = self._xor(
            self._xor(ck[:8], ck[8:]),
            self._xor(ik[:8], ik[8:]),
        )
        return sres, kc
