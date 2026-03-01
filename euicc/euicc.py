"""
Core eUICC implementation.

Models a virtual eUICC chip with ISD-R (root security domain) that manages
ISD-P instances (profile security domains). Each ISD-P holds one eSIM profile.

Reference: GSMA SGP.22 v2.5 - RSP Technical Specification
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from euicc.isdr import ISDRoot
from euicc.isdp import ISDP, ProfileState

logger = logging.getLogger(__name__)


class EUICCState(Enum):
    """eUICC operational states."""
    INITIALIZED = "initialized"
    READY = "ready"
    LOCKED = "locked"
    ERROR = "error"


@dataclass
class EUICCInfo:
    """eUICC Information (EIS) as defined in SGP.22 Section 5.7.3."""
    eid: str
    sv: str = "2.5.0"                 # SGP.22 specification version
    firmware_version: str = "1.0.0"
    uicc_capability: list[str] = field(default_factory=lambda: [
        "contactless", "usim", "isim", "csim",
    ])
    javacardVersion: str = "3.0.5"
    globalplatformVersion: str = "2.3"
    pp_version: str = "2.0"           # Protection Profile version
    sas_accreditation: str = "G0001"  # SAS accreditation number
    free_nvram: int = 512 * 1024      # 512 KB free non-volatile memory


class VirtualEUICC:
    """
    Virtual eUICC implementation.

    The eUICC contains:
    - Exactly one ISD-R (root security domain) - manages the eUICC
    - Zero or more ISD-P instances - each holds one eSIM profile
    - ECASD (eUICC Controlling Authority SD) - manages eUICC certificates

    Lifecycle:
    1. eUICC is manufactured with EID and ISD-R
    2. Profiles are downloaded via RSP (SM-DP+ → LPA → eUICC)
    3. Profiles can be enabled/disabled/deleted
    4. Only one profile can be active at a time
    """

    def __init__(
        self,
        eid: Optional[str] = None,
        profile_dir: str = "/var/lib/vphone/profiles",
        key_dir: str = "/var/lib/vphone/keys",
    ):
        self.eid = eid or os.environ.get(
            "VPHONE_EUICC_EID",
            "89001012012341234000000000000001",
        )
        self.profile_dir = Path(profile_dir)
        self.key_dir = Path(key_dir)
        self.state = EUICCState.INITIALIZED

        self.info = EUICCInfo(eid=self.eid)
        self.isd_r = ISDRoot(eid=self.eid, key_dir=str(self.key_dir))
        self.profiles: dict[str, ISDP] = {}  # iccid -> ISDP
        self._active_iccid: Optional[str] = None

        self.profile_dir.mkdir(parents=True, exist_ok=True)
        logger.info("VirtualEUICC created with EID=%s", self.eid)

    def initialize(self) -> None:
        """Initialize the eUICC, loading any persisted profiles."""
        logger.info("Initializing eUICC...")
        self.isd_r.initialize()
        self._load_profiles()
        self.state = EUICCState.READY
        logger.info(
            "eUICC ready. %d profile(s) loaded, active=%s",
            len(self.profiles),
            self._active_iccid,
        )

    def _load_profiles(self) -> None:
        """Load persisted eSIM profiles from disk."""
        for profile_path in self.profile_dir.glob("*.json"):
            try:
                with open(profile_path) as f:
                    data = json.load(f)
                isdp = ISDP.from_dict(data)
                self.profiles[isdp.iccid] = isdp
                if isdp.state == ProfileState.ENABLED:
                    self._active_iccid = isdp.iccid
                logger.info("Loaded profile ICCID=%s state=%s", isdp.iccid, isdp.state.value)
            except Exception:
                logger.exception("Failed to load profile from %s", profile_path)

    def _save_profile(self, isdp: ISDP) -> None:
        """Persist an eSIM profile to disk."""
        path = self.profile_dir / f"{isdp.iccid}.json"
        with open(path, "w") as f:
            json.dump(isdp.to_dict(), f, indent=2)

    def _delete_profile_file(self, iccid: str) -> None:
        """Remove a profile from disk."""
        path = self.profile_dir / f"{iccid}.json"
        path.unlink(missing_ok=True)

    # -- Profile management (SGP.22 ES10 interface) -----------------------

    def install_profile(self, profile_data: dict) -> ISDP:
        """
        Install a new eSIM profile (Bound Profile Package).

        Called by the LPA after downloading from SM-DP+ via ES9+.
        Creates a new ISD-P and installs the profile into it.

        Args:
            profile_data: Decoded profile package containing IMSI, Ki, OPc, etc.

        Returns:
            The created ISD-P instance.
        """
        self._require_ready()

        iccid = profile_data["iccid"]
        if iccid in self.profiles:
            raise ValueError(f"Profile with ICCID {iccid} already installed")

        # Check available memory
        required_size = profile_data.get("profile_size", 64 * 1024)
        if required_size > self.info.free_nvram:
            raise MemoryError(
                f"Insufficient eUICC memory: need {required_size}, have {self.info.free_nvram}"
            )

        # Create ISD-P and install profile
        isdp = ISDP(
            iccid=iccid,
            imsi=profile_data["imsi"],
            ki=profile_data["ki"],
            opc=profile_data["opc"],
            mcc=profile_data.get("mcc", "001"),
            mnc=profile_data.get("mnc", "01"),
            spn=profile_data.get("spn", "Virtual Operator"),
            msisdn=profile_data.get("msisdn"),
            impi=profile_data.get("impi"),
            impu=profile_data.get("impu"),
            home_domain=profile_data.get("home_domain"),
            state=ProfileState.DISABLED,
            aid=profile_data.get("aid", uuid.uuid4().hex[:32]),
        )

        self.profiles[iccid] = isdp
        self.info.free_nvram -= required_size
        self._save_profile(isdp)

        logger.info("Installed profile ICCID=%s IMSI=%s", iccid, isdp.imsi)
        return isdp

    def enable_profile(self, iccid: str) -> bool:
        """
        Enable a profile (SGP.22 EnableProfile).

        Disables the currently active profile (if any) and enables the
        requested profile. Only one profile may be active at a time.
        """
        self._require_ready()

        if iccid not in self.profiles:
            raise KeyError(f"Profile {iccid} not found")

        target = self.profiles[iccid]
        if target.state == ProfileState.ENABLED:
            return True  # already enabled

        # Disable current active profile
        if self._active_iccid and self._active_iccid in self.profiles:
            current = self.profiles[self._active_iccid]
            current.state = ProfileState.DISABLED
            self._save_profile(current)
            logger.info("Disabled profile ICCID=%s", self._active_iccid)

        # Enable target
        target.state = ProfileState.ENABLED
        self._active_iccid = iccid
        self._save_profile(target)

        logger.info("Enabled profile ICCID=%s", iccid)
        return True

    def disable_profile(self, iccid: str) -> bool:
        """Disable a profile (SGP.22 DisableProfile)."""
        self._require_ready()

        if iccid not in self.profiles:
            raise KeyError(f"Profile {iccid} not found")

        target = self.profiles[iccid]
        if target.state == ProfileState.DISABLED:
            return True

        target.state = ProfileState.DISABLED
        self._save_profile(target)

        if self._active_iccid == iccid:
            self._active_iccid = None

        logger.info("Disabled profile ICCID=%s", iccid)
        return True

    def delete_profile(self, iccid: str) -> bool:
        """Delete a profile (SGP.22 DeleteProfile)."""
        self._require_ready()

        if iccid not in self.profiles:
            raise KeyError(f"Profile {iccid} not found")

        if self._active_iccid == iccid:
            self._active_iccid = None

        del self.profiles[iccid]
        self._delete_profile_file(iccid)

        logger.info("Deleted profile ICCID=%s", iccid)
        return True

    def get_active_profile(self) -> Optional[ISDP]:
        """Return the currently enabled profile, or None."""
        if self._active_iccid and self._active_iccid in self.profiles:
            return self.profiles[self._active_iccid]
        return None

    def list_profiles(self) -> list[dict]:
        """List all installed profiles (SGP.22 GetProfilesInfo)."""
        self._require_ready()
        return [p.to_summary() for p in self.profiles.values()]

    def get_euicc_info(self) -> dict:
        """Return eUICC information (SGP.22 GetEUICCInfo)."""
        return {
            "eid": self.info.eid,
            "sv": self.info.sv,
            "firmware_version": self.info.firmware_version,
            "uicc_capability": self.info.uicc_capability,
            "javacard_version": self.info.javacardVersion,
            "globalplatform_version": self.info.globalplatformVersion,
            "free_nvram": self.info.free_nvram,
            "installed_profiles": len(self.profiles),
            "active_iccid": self._active_iccid,
            "state": self.state.value,
        }

    def _require_ready(self) -> None:
        if self.state != EUICCState.READY:
            raise RuntimeError(f"eUICC not ready (state={self.state.value})")
