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
import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable, Awaitable, TYPE_CHECKING

if TYPE_CHECKING:
    from ims.sms import SMSoverIMS

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


@dataclass
class DataCall:
    """Active data call (PDP context)."""
    cid: int = 1
    active: int = 2        # 0=inactive, 1=dormant, 2=active
    call_type: str = "IP"  # IP, IPV6, IPV4V6
    ifname: str = "rmnet0"
    addresses: list[str] = field(default_factory=lambda: ["10.45.0.2"])
    dnses: list[str] = field(default_factory=lambda: ["172.28.0.50"])
    gateways: list[str] = field(default_factory=lambda: ["10.45.0.1"])


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
        self.data_calls: list[DataCall] = []
        self.imei = os.environ.get("VPHONE_IMEI", "358240051111110")
        self._indication_callback: Optional[Callable[[int, dict], Awaitable[None]]] = None
        self._registration_task: Optional[asyncio.Task] = None
        self._sms_service: Optional[SMSoverIMS] = None

    def set_indication_callback(self, cb: Callable[[int, dict], Awaitable[None]]) -> None:
        """Set callback for unsolicited indications."""
        self._indication_callback = cb

    def set_sms_service(self, sms: SMSoverIMS) -> None:
        """Set the SMS-over-IMS service for MO/MT SMS routing."""
        self._sms_service = sms

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
            # Start simulated network registration
            self._registration_task = asyncio.create_task(self._simulate_registration())
        else:
            self.sim_status.card_state = 0  # absent
            logger.info("No SIM present")

    async def power_off(self) -> None:
        """Power off the virtual radio."""
        logger.info("Radio HAL: powering off")
        self.radio_state = RadioState.OFF
        self.registration = NetworkRegistration()
        self.data_calls.clear()
        if self._registration_task:
            self._registration_task.cancel()
            self._registration_task = None

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

    async def get_imei(self) -> str:
        """IRadio::getImei() - Return device IMEI."""
        return self.imei

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

    async def sim_io(self, command: int, file_id: int, path: str,
                     p1: int, p2: int, p3: int,
                     data: str = "", pin2: str = "", aid: str = "") -> dict:
        """
        IRadio::iccIOForApp() - Perform a SIM I/O command.

        Maps to ISO 7816-4 APDU commands for file access.
        """
        # Build APDU from SIM_IO parameters
        # command: 0xC0=GET_RESPONSE, 0xB0=READ_BINARY, 0xB2=READ_RECORD,
        #          0xD6=UPDATE_BINARY, 0xDC=UPDATE_RECORD, 0xA4=SELECT
        apdu = f"00{command:02x}{p1:02x}{p2:02x}"
        if p3 > 0:
            apdu += f"{p3:02x}"
        if data:
            apdu += data

        resp = await self._send_euicc_message({
            "type": "apdu",
            "data": apdu,
        })

        sw = resp.get("sw", "9000")
        return {
            "sw1": int(sw[:2], 16),
            "sw2": int(sw[2:4], 16),
            "simResponse": resp.get("data", ""),
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

    async def send_sms(self, smsc_pdu: str, pdu: str) -> dict:
        """
        IRadio::sendSms() - Send an SMS message.

        Routes through SMSoverIMS for SIP MESSAGE delivery if available,
        otherwise returns a placeholder success.
        """
        logger.info("Radio HAL: sendSms (pdu=%s...)", pdu[:20] if pdu else "empty")

        if self._sms_service:
            return await self._sms_service.send_sms(smsc_pdu, pdu)

        # Fallback when SMS service is not wired
        return {
            "messageRef": 1,
            "ackPdu": "",
            "errorCode": 0,
        }

    async def deliver_incoming_sms(self, from_number: str, to_number: str,
                                   text: str) -> None:
        """
        Deliver an incoming SMS to Android via NEW_SMS unsolicited indication.

        Called by SMSoverIMS when a SIP MESSAGE is received (MT-SMS path).
        Builds an SMS-DELIVER TPDU and sends it via RIL unsolicited NEW_SMS.
        """
        from ims.sms_pdu import SMSDeliver, build_pdu_for_ril

        deliver = SMSDeliver.create(from_number=from_number, text=text)
        tpdu = deliver.to_bytes()
        pdu_hex = build_pdu_for_ril(tpdu)

        logger.info("Radio HAL: delivering MT-SMS from=%s text='%s'",
                     from_number, text[:30])

        # Send NEW_SMS unsolicited indication (RIL_UNSOL_RESPONSE_NEW_SMS = 1003)
        await self._send_indication(1003, {"pdu": pdu_hex})

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

    async def get_data_call_list(self) -> dict:
        """IRadio::getDataCallList() - Return active data calls."""
        return {
            "calls": [
                {
                    "cid": dc.cid,
                    "active": dc.active,
                    "type": dc.call_type,
                    "ifname": dc.ifname,
                    "addresses": dc.addresses,
                    "dnses": dc.dnses,
                    "gateways": dc.gateways,
                }
                for dc in self.data_calls
            ],
        }

    async def set_initial_attach_apn(self, data: dict) -> dict:
        """IRadio::setInitialAttachApn() - Set the initial attach APN."""
        logger.info("Radio HAL: setInitialAttachApn(%s)", data.get("apn", ""))
        return {"success": True}

    async def set_data_profile(self, data: dict) -> dict:
        """IRadio::setDataProfile() - Set data connection profiles."""
        logger.info("Radio HAL: setDataProfile")
        return {"success": True}

    async def get_current_calls(self) -> dict:
        """IRadio::getCurrentCalls() - Return active voice calls."""
        # Voice calls will be implemented in Phase 6
        return {"calls": []}

    def get_radio_state(self) -> dict:
        """Return the current radio state for the management API."""
        return {
            "radioState": self.radio_state.name,
            "simPresent": self.sim_status.card_state == 1,
            "registration": {
                "state": self.registration.reg_state.name,
                "rat": self.registration.rat.name,
                "mcc": self.registration.mcc,
                "mnc": self.registration.mnc,
            },
            "signalStrength": {
                "rsrp": -95,
                "rsrq": -10,
            },
            "imei": self.imei,
            "dataCallsActive": len(self.data_calls),
        }

    async def _simulate_registration(self) -> None:
        """
        Simulate network registration after radio power-on.

        Transitions: NOT_SEARCHING → SEARCHING → REGISTERED (LTE).
        This simulates what a real modem does when it attaches to a network.
        """
        try:
            # Phase 1: Searching
            await asyncio.sleep(1)
            self.registration.reg_state = RegState.NOT_REG_SEARCHING
            logger.info("Radio: searching for network...")
            await self._send_indication(1001, {})  # NETWORK_STATE_CHANGED

            # Phase 2: Registered on LTE
            await asyncio.sleep(2)
            self.registration.reg_state = RegState.REG_HOME
            self.registration.rat = NetworkType.LTE
            self.registration.lac = 0x0001
            self.registration.cid = 0x00000101
            logger.info(
                "Radio: registered on %s%s (LTE)",
                self.registration.mcc, self.registration.mnc,
            )
            await self._send_indication(1001, {})  # NETWORK_STATE_CHANGED

            # Phase 3: Establish default data call
            await asyncio.sleep(1)
            self.data_calls = [DataCall()]
            logger.info("Radio: default data call established on rmnet0")

        except asyncio.CancelledError:
            pass

    async def _send_indication(self, indication_id: int, data: dict) -> None:
        """Send an unsolicited indication to the RIL bridge client."""
        if self._indication_callback:
            await self._indication_callback(indication_id, data)

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
