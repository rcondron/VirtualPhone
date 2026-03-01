"""
ISD-P (Issuer Security Domain - Profile) implementation.

Each ISD-P holds exactly one eSIM profile. A profile contains the telecom
credentials (IMSI, Ki, OPc) and configuration needed to authenticate with
a mobile network.

Reference: GSMA SGP.22 Section 4.1, ETSI TS 102.221
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ProfileState(Enum):
    """Profile lifecycle states (SGP.22 Section 3.1)."""
    DISABLED = "disabled"
    ENABLED = "enabled"
    DELETING = "deleting"


class ProfileClass(Enum):
    """Profile class types."""
    PROVISIONING = "provisioning"
    OPERATIONAL = "operational"
    TEST = "test"


@dataclass
class ISDP:
    """
    ISD-P - holds a single eSIM profile.

    Contains all credentials and configuration for network authentication:
    - USIM application (IMSI, Ki, OPc for 3G/4G/5G auth)
    - ISIM application (IMS credentials for VoLTE/VoWiFi)
    - Network access rules and operator configuration
    """

    # -- Identity --
    iccid: str            # Integrated Circuit Card Identifier (19-20 digits)
    imsi: str             # International Mobile Subscriber Identity (15 digits)
    aid: str              # Application Identifier for the ISD-P

    # -- Authentication credentials --
    ki: str               # Authentication key Ki (128-bit hex)
    opc: str              # Operator variant key OPc (128-bit hex)

    # -- Network information --
    mcc: str = "001"      # Mobile Country Code
    mnc: str = "01"       # Mobile Network Code
    spn: str = "Virtual"  # Service Provider Name

    # -- Optional subscriber fields --
    msisdn: Optional[str] = None     # Phone number (E.164)
    gid1: Optional[str] = None       # Group Identifier Level 1
    gid2: Optional[str] = None       # Group Identifier Level 2

    # -- IMS credentials (ISIM) --
    impi: Optional[str] = None       # IMS Private Identity (e.g., user@ims.domain)
    impu: Optional[str] = None       # IMS Public Identity (e.g., sip:user@ims.domain)
    home_domain: Optional[str] = None  # IMS home network domain

    # -- State --
    state: ProfileState = ProfileState.DISABLED
    profile_class: ProfileClass = ProfileClass.OPERATIONAL

    # -- Sequence numbers for replay protection --
    sqn: int = 0  # Sequence number for Milenage (48-bit)

    def increment_sqn(self) -> int:
        """Increment and return the sequence number (for AKA auth)."""
        self.sqn += 1
        return self.sqn

    def get_usim_data(self) -> dict:
        """Return USIM application data for authentication."""
        return {
            "imsi": self.imsi,
            "ki": self.ki,
            "opc": self.opc,
            "sqn": self.sqn,
            "mcc": self.mcc,
            "mnc": self.mnc,
        }

    def get_isim_data(self) -> Optional[dict]:
        """Return ISIM application data for IMS registration."""
        if not self.impi:
            # Derive IMS identities from IMSI if not explicitly set
            domain = self.home_domain or f"ims.mnc{self.mnc}.mcc{self.mcc}.3gppnetwork.org"
            return {
                "impi": f"{self.imsi}@{domain}",
                "impu": f"sip:{self.imsi}@{domain}",
                "home_domain": domain,
            }
        return {
            "impi": self.impi,
            "impu": self.impu,
            "home_domain": self.home_domain,
        }

    def to_dict(self) -> dict:
        """Serialize to dictionary for persistence."""
        return {
            "iccid": self.iccid,
            "imsi": self.imsi,
            "aid": self.aid,
            "ki": self.ki,
            "opc": self.opc,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "spn": self.spn,
            "msisdn": self.msisdn,
            "gid1": self.gid1,
            "gid2": self.gid2,
            "impi": self.impi,
            "impu": self.impu,
            "home_domain": self.home_domain,
            "state": self.state.value,
            "profile_class": self.profile_class.value,
            "sqn": self.sqn,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ISDP:
        """Deserialize from dictionary."""
        return cls(
            iccid=data["iccid"],
            imsi=data["imsi"],
            aid=data.get("aid", ""),
            ki=data["ki"],
            opc=data["opc"],
            mcc=data.get("mcc", "001"),
            mnc=data.get("mnc", "01"),
            spn=data.get("spn", "Virtual"),
            msisdn=data.get("msisdn"),
            gid1=data.get("gid1"),
            gid2=data.get("gid2"),
            impi=data.get("impi"),
            impu=data.get("impu"),
            home_domain=data.get("home_domain"),
            state=ProfileState(data.get("state", "disabled")),
            profile_class=ProfileClass(data.get("profile_class", "operational")),
            sqn=data.get("sqn", 0),
        )

    def to_summary(self) -> dict:
        """Return a summary for listing (no sensitive keys)."""
        return {
            "iccid": self.iccid,
            "imsi": self.imsi,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "spn": self.spn,
            "msisdn": self.msisdn,
            "state": self.state.value,
            "profile_class": self.profile_class.value,
        }
