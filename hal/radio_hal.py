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
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional, Callable, Awaitable, TYPE_CHECKING

if TYPE_CHECKING:
    from ims.sms import SMSoverIMS
    from ims.volte import VoLTECallManager
    from ims.supplementary import CallForwardingManager, USSDHandler

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


class CallState(IntEnum):
    """Android call state values (from DriverCall.State)."""
    ACTIVE = 0
    HOLDING = 1
    DIALING = 2
    ALERTING = 3
    INCOMING = 4
    WAITING = 5


@dataclass
class VoiceCall:
    """An active voice call tracked by the Radio HAL."""
    index: int = 1             # 1-based call index
    state: CallState = CallState.DIALING
    is_mt: bool = False        # True = mobile-terminated (incoming)
    is_mpty: bool = False      # Multi-party (conference)
    number: str = ""           # Remote party number
    name: str = ""             # Remote party name (if available)
    number_presentation: int = 0  # 0=allowed, 1=restricted, 2=not available
    sip_call_id: str = ""      # SIP Call-ID for IMS correlation

    def to_ril_dict(self) -> dict:
        """Serialize to RIL getCurrentCalls format."""
        return {
            "state": self.state.value,
            "index": self.index,
            "isMT": self.is_mt,
            "isMpty": self.is_mpty,
            "number": self.number,
            "name": self.name,
            "numberPresentation": self.number_presentation,
        }


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
        self._call_manager: Optional[VoLTECallManager] = None
        self.voice_calls: list[VoiceCall] = []
        self._next_call_index: int = 1
        self._cf_manager: Optional[CallForwardingManager] = None
        self._ussd_handler: Optional[USSDHandler] = None
        self._muted: bool = False

    def set_indication_callback(self, cb: Callable[[int, dict], Awaitable[None]]) -> None:
        """Set callback for unsolicited indications."""
        self._indication_callback = cb

    def set_sms_service(self, sms: SMSoverIMS) -> None:
        """Set the SMS-over-IMS service for MO/MT SMS routing."""
        self._sms_service = sms

    def set_call_manager(self, mgr: VoLTECallManager) -> None:
        """Set the VoLTE call manager for voice call routing."""
        self._call_manager = mgr

    def set_call_forwarding(self, cf: CallForwardingManager) -> None:
        """Set the call forwarding manager."""
        self._cf_manager = cf

    def set_ussd_handler(self, ussd: USSDHandler) -> None:
        """Set the USSD handler."""
        self._ussd_handler = ussd

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
            # Notify Android that SIM status changed
            await self._send_indication(1019, {})  # SIM_STATUS_CHANGED
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
        self.voice_calls.clear()
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
        return {
            "calls": [c.to_ril_dict() for c in self.voice_calls],
        }

    async def dial(self, number: str, clir: int = 0) -> dict:
        """
        IRadio::dial() - Initiate an outgoing (MO) voice call.

        Creates a VoiceCall in DIALING state and triggers SIP INVITE
        via the VoLTE call manager.
        """
        logger.info("Radio HAL: dial(%s)", number)

        call = VoiceCall(
            index=self._next_call_index,
            state=CallState.DIALING,
            is_mt=False,
            number=number,
        )
        self._next_call_index += 1
        self.voice_calls.append(call)

        # Notify Android of call state change
        await self._send_indication(1001, {})  # CALL_STATE_CHANGED uses same id

        # Start SIP INVITE via VoLTE call manager
        if self._call_manager:
            sip_call_id = await self._call_manager.initiate_call(number, call.index)
            if sip_call_id:
                call.sip_call_id = sip_call_id
            else:
                # INVITE failed — mark call as ended
                self.voice_calls.remove(call)
                await self._send_indication(1001, {})
                return {"success": False, "error": "INVITE failed"}

        return {"success": True, "callIndex": call.index}

    async def answer(self) -> dict:
        """IRadio::acceptCall() - Answer an incoming (MT) call."""
        for call in self.voice_calls:
            if call.state == CallState.INCOMING:
                logger.info("Radio HAL: answer call %d from %s", call.index, call.number)
                call.state = CallState.ACTIVE
                await self._send_indication(1001, {})

                if self._call_manager:
                    await self._call_manager.answer_call(call.sip_call_id)

                return {"success": True}

        return {"success": False, "error": "No incoming call"}

    async def hangup(self, call_index: int) -> dict:
        """IRadio::hangup() - Terminate a voice call."""
        for call in self.voice_calls:
            if call.index == call_index:
                logger.info("Radio HAL: hangup call %d", call_index)

                if self._call_manager and call.sip_call_id:
                    await self._call_manager.hangup_call(call.sip_call_id)

                self.voice_calls.remove(call)
                await self._send_indication(1001, {})
                return {"success": True}

        return {"success": False, "error": "Call not found"}

    async def switch_waiting_or_holding_and_active(self) -> dict:
        """
        IRadio::switchWaitingOrHoldingAndActive()

        Swap between active and held/waiting calls:
        - If a call is WAITING: answer it and hold the active call
        - If a call is HELD: resume it and hold the active call
        """
        waiting = None
        for vc in self.voice_calls:
            if vc.state == CallState.WAITING:
                waiting = vc
                break

        if waiting:
            # Answer waiting call: hold active, accept waiting
            for vc in self.voice_calls:
                if vc.state == CallState.ACTIVE:
                    vc.state = CallState.HOLDING
                    if self._call_manager:
                        await self._call_manager.hold_call(vc.sip_call_id)
            waiting.state = CallState.ACTIVE
            if self._call_manager and waiting.sip_call_id:
                await self._call_manager.answer_call(waiting.sip_call_id)
        elif self._call_manager:
            # Swap held and active
            await self._call_manager.swap_calls()

        await self._send_indication(1001, {})
        return {"success": True}

    async def conference(self) -> dict:
        """
        IRadio::conference() — Merge active and held calls.

        Creates a multi-party conference call.
        """
        if self._call_manager:
            result = await self._call_manager.conference_calls()
            return {"success": result}
        return {"success": False, "error": "No call manager"}

    async def separate_connection(self, call_index: int) -> dict:
        """
        IRadio::separateConnection() — Remove a party from conference.

        Splits a participant out of a multi-party call. The separated
        call becomes held while the conference continues.
        """
        for vc in self.voice_calls:
            if vc.index == call_index and vc.is_mpty:
                vc.is_mpty = False
                vc.state = CallState.HOLDING
                if self._call_manager:
                    await self._call_manager.hold_call(vc.sip_call_id)
                await self._send_indication(1001, {})
                return {"success": True}
        return {"success": False, "error": "Call not in conference"}

    async def explicit_call_transfer(self) -> dict:
        """
        IRadio::explicitCallTransfer() — Transfer call.

        Connects the held and active calls together and disconnects
        this phone from both (Explicit Call Transfer / ECT).
        """
        active = None
        held = None
        for vc in self.voice_calls:
            if vc.state == CallState.ACTIVE:
                active = vc
            elif vc.state == CallState.HOLDING:
                held = vc

        if not active or not held:
            return {"success": False, "error": "Need active + held call"}

        if self._call_manager:
            # Transfer the held call to the remote party of the active call
            result = await self._call_manager.transfer_call(
                held.sip_call_id, active.number
            )
            if result:
                self.voice_calls.remove(active)
                self.voice_calls.remove(held)
                await self._send_indication(1001, {})
                return {"success": True}

        return {"success": False, "error": "Transfer failed"}

    async def send_ussd(self, ussd_string: str) -> dict:
        """
        IRadio::sendUssd() — Send a USSD code.

        Processes the USSD code locally or forwards to network.
        Returns a dict with USSD response type and message.
        """
        logger.info("Radio HAL: sendUssd(%s)", ussd_string)

        if self._ussd_handler:
            result = self._ussd_handler.send_ussd(ussd_string)
            # Send RIL_UNSOL_ON_USSD indication
            await self._send_indication(1028, {
                "type": result.get("type", 0),
                "message": result.get("message", ""),
            })
            return {"success": True}

        return {"success": False, "error": "USSD not available"}

    async def cancel_ussd(self) -> dict:
        """IRadio::cancelPendingUssd() — Cancel active USSD session."""
        if self._ussd_handler:
            self._ussd_handler.cancel_ussd()
            return {"success": True}
        return {"success": False}

    async def set_call_forward(self, action: int, reason: int,
                                number: str, time_seconds: int) -> dict:
        """
        IRadio::setCallForward() — Configure call forwarding.

        Args:
            action: 0=disable, 1=enable, 3=register, 4=erase
            reason: 0=CFU, 1=CFB, 2=CFNR, 3=CFNRc, 4=all, 5=all_conditional
            number: Forwarding destination number
            time_seconds: No-reply timeout (CFNR only)
        """
        if not self._cf_manager:
            return {"success": False, "error": "CF not available"}

        from ims.supplementary import CallForwardReason

        try:
            cf_reason = CallForwardReason(reason)
        except ValueError:
            return {"success": False, "error": f"Invalid reason: {reason}"}

        if action == 0:
            self._cf_manager.disable_rule(cf_reason)
        elif action == 1:
            self._cf_manager.enable_rule(cf_reason)
        elif action == 3:
            self._cf_manager.set_rule(cf_reason, number, time_seconds)
        elif action == 4:
            self._cf_manager.erase_rule(cf_reason)
        else:
            return {"success": False, "error": f"Invalid action: {action}"}

        logger.info("Radio HAL: CF action=%d reason=%s number=%s",
                     action, cf_reason.name, number)
        return {"success": True}

    async def query_call_forward(self, reason: int) -> dict:
        """
        IRadio::getCallForwardStatus() — Query call forwarding rules.
        """
        if not self._cf_manager:
            return {"rules": []}

        from ims.supplementary import CallForwardReason
        try:
            cf_reason = CallForwardReason(reason)
        except ValueError:
            return {"rules": []}

        rules = self._cf_manager.query_rule(cf_reason)
        return {"rules": rules}

    async def set_mute(self, mute: bool) -> dict:
        """IRadio::setMute() — Mute or unmute the microphone."""
        self._muted = mute
        logger.info("Radio HAL: mute=%s", mute)
        return {"success": True}

    async def get_mute(self) -> dict:
        """IRadio::getMute() — Get current mute state."""
        return {"muted": self._muted}

    async def hangup_all(self) -> dict:
        """Hangup all active calls."""
        for call in list(self.voice_calls):
            if self._call_manager and call.sip_call_id:
                await self._call_manager.hangup_call(call.sip_call_id)
        self.voice_calls.clear()
        await self._send_indication(1001, {})
        return {"success": True}

    async def update_call_state(self, call_index: int,
                                new_state: CallState) -> None:
        """Update the state of a call (called by VoLTE call manager)."""
        for call in self.voice_calls:
            if call.index == call_index:
                old_state = call.state
                call.state = new_state
                logger.info("Radio HAL: call %d %s → %s",
                            call_index, old_state.name, new_state.name)
                await self._send_indication(1001, {})
                return

    async def incoming_call(self, number: str, sip_call_id: str) -> None:
        """
        Notify Android of an incoming (MT) call.

        Called by VoLTE call manager when a SIP INVITE is received.
        Checks call forwarding rules before presenting the call.
        """
        # Check call forwarding (unconditional)
        if self._cf_manager:
            from ims.supplementary import CallForwardReason
            fwd_number = self._cf_manager.should_forward(
                CallForwardReason.UNCONDITIONAL
            )
            if fwd_number:
                logger.info("Radio HAL: forwarding call from %s → %s (CFU)",
                            number, fwd_number)
                if self._call_manager:
                    await self._call_manager.hangup_call(sip_call_id)
                    await self._call_manager.initiate_call(fwd_number, 0)
                return

        # Determine call state (INCOMING if idle, WAITING if active call exists)
        has_active = any(vc.state == CallState.ACTIVE for vc in self.voice_calls)
        call_state = CallState.WAITING if has_active else CallState.INCOMING

        call = VoiceCall(
            index=self._next_call_index,
            state=call_state,
            is_mt=True,
            number=number,
            sip_call_id=sip_call_id,
        )
        self._next_call_index += 1
        self.voice_calls.append(call)

        logger.info("Radio HAL: incoming call %d from %s (state=%s)",
                     call.index, number, call_state.name)
        # RIL_UNSOL_CALL_RING = 1002
        await self._send_indication(1002, {"isGsm": False})
        await self._send_indication(1001, {})

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

            # Phase 4: Send NITZ time (network time sync)
            now = datetime.now(timezone.utc)
            nitz_str = now.strftime("%y/%m/%d,%H:%M:%S+00")
            await self._send_indication(1008, {"nitz": nitz_str})
            logger.info("Radio: NITZ time sent: %s", nitz_str)

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
