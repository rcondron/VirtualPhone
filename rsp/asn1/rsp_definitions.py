"""
ASN.1 definitions for RSP (SGP.22) messages.

Defines the data structures used in ES9+ and ES10 interfaces for
eSIM profile provisioning. Based on GSMA SGP.22 v2.5 ASN.1 module.

These are simplified definitions using Python dataclasses that mirror
the ASN.1 structures. For full ASN.1 encoding/decoding, the asn1tools
library is used with the schema definitions.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# SGP.22 ASN.1 OIDs
OID_RSP = "2.16.840.1.101.2.1"
OID_GSMA_RSP = "1.3.6.1.4.1.31746"

# ASN.1 schema for RSP messages (simplified DER encoding helpers)
RSP_ASN1_SCHEMA = """
RSPDefinitions DEFINITIONS AUTOMATIC TAGS ::= BEGIN

-- ES9+ InitiateAuthentication
InitiateAuthenticationRequest ::= SEQUENCE {
    euiccChallenge      OCTET STRING (SIZE (16)),
    smdpAddress         UTF8String,
    euiccInfo1          EUICCInfo1
}

EUICCInfo1 ::= SEQUENCE {
    svn                 VersionType,
    euiccCiPKIdListForVerification  SEQUENCE OF SubjectKeyIdentifier,
    euiccCiPKIdListForSigning       SEQUENCE OF SubjectKeyIdentifier
}

VersionType ::= OCTET STRING (SIZE (3))
SubjectKeyIdentifier ::= OCTET STRING

-- ES9+ AuthenticateClient
AuthenticateClientRequest ::= SEQUENCE {
    transactionId       UTF8String,
    authenticateServerResponse  AuthenticateServerResponse
}

AuthenticateServerResponse ::= SEQUENCE {
    transactionId       UTF8String,
    serverSigned1       ServerSigned1,
    serverSignature1    OCTET STRING,
    euiccCiPKIdToBeUsed SubjectKeyIdentifier,
    serverCertificate   Certificate
}

ServerSigned1 ::= SEQUENCE {
    transactionId       UTF8String,
    euiccChallenge      OCTET STRING (SIZE (16)),
    serverAddress       UTF8String,
    serverChallenge     OCTET STRING (SIZE (16))
}

Certificate ::= OCTET STRING

-- ES9+ GetBoundProfilePackage
GetBoundProfilePackageRequest ::= SEQUENCE {
    transactionId       UTF8String,
    prepareDownloadResponse  PrepareDownloadResponse
}

PrepareDownloadResponse ::= SEQUENCE {
    transactionId       UTF8String,
    hashCc              OCTET STRING OPTIONAL,
    smdpSigned2         OCTET STRING,
    smdpSignature2      OCTET STRING
}

-- Bound Profile Package
BoundProfilePackage ::= SEQUENCE {
    initialiseSecureChannelRequest  OCTET STRING,
    firstSequenceOf87              OCTET STRING,
    sequenceOf88                   OCTET STRING,
    secondSequenceOf87             OCTET STRING OPTIONAL,
    sequenceOf86                   OCTET STRING OPTIONAL
}

-- Profile metadata
ProfileMetadata ::= SEQUENCE {
    iccid               OCTET STRING (SIZE (10)),
    serviceProviderName UTF8String,
    profileName         UTF8String OPTIONAL,
    iconType            INTEGER OPTIONAL,
    icon                OCTET STRING OPTIONAL,
    profileClass        ProfileClass
}

ProfileClass ::= ENUMERATED {
    test         (0),
    provisioning (1),
    operational  (2)
}

-- Notification
PendingNotification ::= CHOICE {
    profileInstallationResult   SEQUENCE {
        profileInstallationResultData   ProfileInstallResultData,
        euiccSignPIR                    OCTET STRING
    },
    otherSignedNotification    SEQUENCE {
        tbsOtherNotification   OCTET STRING,
        euiccNotificationSignature  OCTET STRING
    }
}

ProfileInstallResultData ::= SEQUENCE {
    transactionId           UTF8String,
    notificationMetadata    NotificationMetadata,
    smdpOid                 OBJECT IDENTIFIER OPTIONAL,
    finalResult             CHOICE {
        successResult       SuccessResult,
        errorResult         ErrorResult
    }
}

NotificationMetadata ::= SEQUENCE {
    seqNumber               INTEGER,
    profileManagementOperation  INTEGER,
    notificationAddress     UTF8String,
    iccid                   OCTET STRING (SIZE (10)) OPTIONAL
}

SuccessResult ::= SEQUENCE {
    aid                     OCTET STRING,
    simaResponse            OCTET STRING OPTIONAL
}

ErrorResult ::= SEQUENCE {
    bppCommandId            INTEGER,
    errorReason             INTEGER,
    simaResponse            OCTET STRING OPTIONAL
}

END
"""


class ResultCode(IntEnum):
    """SGP.22 result codes."""
    OK = 0
    SUBJECT_UNKNOWN = 1
    INSUFFICIENT_MEMORY = 2
    ALREADY_INSTALLED = 3
    NOT_FOUND = 4
    REFUSED = 5
    CONFIRMATION_CODE_REQUIRED = 6
    WRONG_CONFIRMATION_CODE = 7
    INSTALL_FAILED = 8
    INTERNAL_ERROR = 127


@dataclass
class EUICCInfo1:
    """eUICC information sent during InitiateAuthentication."""
    svn: bytes = field(default_factory=lambda: bytes([2, 5, 0]))  # v2.5.0
    euicc_ci_pk_id_for_verify: list[bytes] = field(default_factory=list)
    euicc_ci_pk_id_for_sign: list[bytes] = field(default_factory=list)


@dataclass
class EUICCInfo2:
    """Extended eUICC information."""
    profile_version: str = "2.1.0"
    svn: str = "2.5.0"
    firmware_version: str = "1.0.0"
    ext_card_resource: bytes = b""
    uicc_capability: bytes = b""
    javacardVersion: str = "3.0.5"
    globalplatformVersion: str = "2.3"
    pp_version: str = "2.0"
    sas_accreditation: str = "G0001"
    free_nvram: int = 512 * 1024


@dataclass
class ServerSigned1:
    """SM-DP+ signed data in AuthenticateServer response."""
    transaction_id: str
    euicc_challenge: bytes
    server_address: str
    server_challenge: bytes


@dataclass
class AuthenticateServerResponse:
    """Response from SM-DP+ to InitiateAuthentication."""
    transaction_id: str
    server_signed1: ServerSigned1
    server_signature1: bytes
    euicc_ci_pk_id: bytes
    server_certificate: bytes


@dataclass
class PrepareDownloadResponse:
    """Response from eUICC PrepareDownload."""
    transaction_id: str
    hash_cc: Optional[bytes] = None
    smdp_signed2: bytes = b""
    smdp_signature2: bytes = b""


@dataclass
class BoundProfilePackage:
    """A complete Bound Profile Package ready for installation."""
    initialise_secure_channel: bytes = b""
    first_sequence_87: bytes = b""
    sequence_88: bytes = b""
    second_sequence_87: Optional[bytes] = None
    sequence_86: Optional[bytes] = None

    # Decoded profile data (after processing)
    profile_metadata: Optional[dict] = None


@dataclass
class ProfileInstallResult:
    """Result of a profile installation operation."""
    transaction_id: str
    iccid: Optional[str] = None
    result_code: ResultCode = ResultCode.OK
    error_reason: Optional[str] = None


def encode_eid(eid: str) -> bytes:
    """Encode EID as BCD bytes."""
    result = b""
    for i in range(0, len(eid), 2):
        d1 = int(eid[i])
        d2 = int(eid[i + 1]) if i + 1 < len(eid) else 0xF
        result += bytes([(d1 << 4) | d2])
    return result


def decode_eid(data: bytes) -> str:
    """Decode EID from BCD bytes."""
    result = ""
    for byte in data:
        result += str((byte >> 4) & 0x0F)
        low = byte & 0x0F
        if low != 0xF:
            result += str(low)
    return result
