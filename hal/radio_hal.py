"""
Android Radio HAL interface.

Bridges the virtual eUICC to Android's telephony framework by implementing
the Radio HAL interface. The Radio HAL (IRadio) is Android's abstraction
for the cellular modem.

In a real device, the Radio HAL talks to the baseband processor via RIL.
In our virtual environment, it communicates with the virtual eUICC daemon
and IMS stack.

Key interfaces:
- IRadio: Main telephony operations
- IRadioResponse: Callbacks for completed operations
- IRadioIndication: Unsolicited notifications

Reference: Android HIDL IRadio (hardware/interfaces/radio/)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class RadioState(IntEnum):
    """Android RadioState values."""
    OFF = 0
    UNAVAILABLE = 1
    ON = 10


class RegState(IntEnum):
    """Android network registration state."""
    NOT_REG_NOT_SEARCHING = 0
    REG_HOME = 1
    NOT_REG_SEARCHING = 2
    REG_DENIED = 3
    UNKNOWN = 4
    REG_ROAMING = 5
    REG_HOME_SMS_ONLY = 10
    REG_ROAMING_SMS_ONLY = 11
    REG_EMERGENCY_ONLY = 12
    REG_HOME_CSFB_NOT_PREF = 13
    REG_ROAMING_CSFB_NOT_PREF = 14


class NetworkType(IntEnum):
    """Android radio technology types."""
    UNKNOWN = 0
    GPRS = 1
    EDGE = 2
    UMTS = 3
    HSDPA = 9
    HSUPA = 10
    HSPA = 11
    LTE = 14
    LTE_CA = 19
    NR = 20  # 5G NR


@dataclass
class SimStatus:
    """SIM card status as reported to Android."""
    card_state: int = 1       # 0=absent, 1=present, 2=error
    pin_state: int = 5        # 5=READY (no PIN required)
    gsm_umts_app_index: int = 0
    ims_app_index: int = 1
    num_applications: int = 2  # USIM + ISIM


@dataclass
class NetworkRegistration:
    """Network registration state."""
    reg_state: RegState = RegState.NOT_REG_NOT_SEARCHING
    rat: NetworkType = NetworkType.UNKNOWN
    mcc: str = ""
    mnc: str = ""
    lac: int = 0
    cid: int = 0


class RadioHAL:
    """
    Virtual Radio HAL implementation.

    Provides the interface that Android's telephony framework expects
    from a cellular modem. Translates Android HAL requests into
    commands for the virtual eUICC and IMS stack.
    """

    def __init__(self, euicc_socket: str = "/run/vphone/euicc.sock"):
        self.euicc_socket = euicc_socket
        self.radio_state = RadioState.OFF
        self.sim_status = SimStatus()
        self.registration = NetworkRegistration()
        self._response_callbacks: dict[str, Callable] = {}
        self._indication_callbacks: dict[str, Callable] = {}

    async def power_on(self) -> None:
        """Power on the virtual radio."""
        logger.info("Radio HAL: powering on")
        self.radio_state = RadioState.ON

        # Check for SIM
        profile = await self._get_active_profile()
        if profile:
            self.sim_status.card_state = 1  # present
            self.registration.mcc = profile.get("mcc", "")
            self.registration.mnc = profile.get("mnc", "")
            logger.info("SIM present: MCC=%s MNC=%s", self.registration.mcc, self.registration.mnc)
        else:
            self.sim_status.card_state = 0  # absent
            logger.info("No SIM present")

    async def power_off(self) -> None:
        """Power off the virtual radio."""
        logger.info("Radio HAL: powering off")
        self.radio_state = RadioState.OFF
        self.registration = NetworkRegistration()

    async def get_sim_status(self) -> dict:
        """IRadio::getIccCardStatus() - Return SIM card status."""
        profile = await self._get_active_profile()

        if profile:
            return {
                "cardState": 1,  # PRESENT
                "pinState": 5,   # READY
                "applications": [
                    {
                        "appType": 2,  # USIM
                        "appState": 5,  # READY
                        "aidPtr": "A0000000871002",
                        "label": profile.get("spn", "Virtual"),
                    },
                    {
                        "appType": 4,  # ISIM
                        "appState": 5,  # READY
                        "aidPtr": "A0000000871004",
                        "label": "ISIM",
                    },
                ],
                "iccid": profile.get("iccid", ""),
                "eid": (await self._get_euicc_info()).get("eid", ""),
            }
        else:
            return {
                "cardState": 0,  # ABSENT
                "applications": [],
            }

    async def get_imsi(self) -> Optional[str]:
        """IRadio::getImsiForApp() - Return IMSI."""
        profile = await self._get_active_profile()
        return profile.get("imsi") if profile else None

    async def get_operator(self) -> dict:
        """IRadio::getOperator() - Return operator information."""
        profile = await self._get_active_profile()
        if profile:
            return {
                "longName": profile.get("spn", "Virtual Operator"),
                "shortName": profile.get("spn", "Virtual")[:8],
                "numeric": f"{profile.get('mcc', '001')}{profile.get('mnc', '01')}",
            }
        return {"longName": "", "shortName": "", "numeric": ""}

    async def get_data_registration_state(self) -> dict:
        """IRadio::getDataRegistrationState() - Return data registration."""
        return {
            "regState": self.registration.reg_state.value,
            "rat": self.registration.rat.value,
            "maxDataCalls": 4,
            "mcc": self.registration.mcc,
            "mnc": self.registration.mnc,
        }

    async def get_voice_registration_state(self) -> dict:
        """IRadio::getVoiceRegistrationState() - Return voice registration."""
        return {
            "regState": self.registration.reg_state.value,
            "rat": self.registration.rat.value,
            "cssSupported": False,
            "mcc": self.registration.mcc,
            "mnc": self.registration.mnc,
        }

    async def get_signal_strength(self) -> dict:
        """IRadio::getSignalStrength() - Return simulated signal strength."""
        return {
            "lte": {
                "signalStrength": 15,   # 0-31
                "rsrp": -95,            # dBm
                "rsrq": -10,            # dB
                "rssnr": 100,           # 0.1 dB units
                "cqi": 10,
                "timingAdvance": 0,
            },
        }

    async def sim_authentication(self, auth_context: int, auth_data: str) -> dict:
        """
        IRadio::requestIccSimAuthentication() - Run SIM authentication.

        This is used for:
        - Network authentication (AKA)
        - IMS authentication
        - EAP-AKA for VoWiFi
        """
        # Forward AUTHENTICATE APDU to eUICC
        resp = await self._send_euicc_message({
            "type": "apdu",
            "data": f"0088{auth_context:02x}00{auth_data}",
        })

        return {
            "sw1": int(resp.get("sw", "0000")[:2], 16),
            "sw2": int(resp.get("sw", "0000")[2:4], 16),
            "simResponse": resp.get("data", ""),
        }

    async def supply_icc_pin(self, pin: str) -> dict:
        """IRadio::supplyIccPinForApp() - Verify PIN."""
        # Virtual eUICC doesn't require PIN by default
        return {"remainingRetries": 3, "success": True}

    async def set_radio_power(self, on: bool) -> None:
        """IRadio::setRadioPower()."""
        if on:
            await self.power_on()
        else:
            await self.power_off()

    async def _get_active_profile(self) -> Optional[dict]:
        """Query the eUICC for the active profile."""
        resp = await self._send_euicc_message({"type": "list_profiles"})
        profiles = resp.get("data", [])
        for p in profiles:
            if p.get("state") == "enabled":
                return p
        return None

    async def _get_euicc_info(self) -> dict:
        """Query the eUICC for device info."""
        resp = await self._send_euicc_message({"type": "get_info"})
        return resp.get("data", {})

    async def _send_euicc_message(self, msg: dict) -> dict:
        """Send a message to the eUICC daemon."""
        try:
            reader, writer = await asyncio.open_unix_connection(self.euicc_socket)
            msg_bytes = json.dumps(msg).encode()
            writer.write(len(msg_bytes).to_bytes(4, "big"))
            writer.write(msg_bytes)
            await writer.drain()

            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, "big")
            resp_bytes = await reader.readexactly(length)
            writer.close()
            await writer.wait_closed()
            return json.loads(resp_bytes)
        except Exception as e:
            logger.error("eUICC communication error: %s", e)
            return {}
