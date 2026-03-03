"""
RIL (Radio Interface Layer) bridge.

Bridges the Android RIL running inside redroid to the virtual eUICC
and telecom stack running on the host. Communication happens over
a TCP socket that emulates the RIL daemon socket.

The bridge:
1. Listens for RIL solicited/unsolicited requests from Android
2. Translates them into commands for the virtual eUICC
3. Sends responses back in the RIL wire format

The C-based RIL shim inside redroid connects to this bridge over TCP
and translates between Android's Parcel protocol and our JSON format.

Wire protocol (JSON over TCP, length-prefixed):
  [4-byte big-endian length][JSON payload]

Request:  {"type": 0, "serial": N, "id": <RIL_REQUEST>, "data": {...}}
Response: {"type": 0, "serial": N, "id": <RIL_REQUEST>, "data": {...}}
Unsol:    {"type": 1, "serial": 0, "id": <RIL_UNSOL>,   "data": {...}}

Reference: Android RIL (hardware/ril/), ril.h
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from hal.radio_hal import RadioHAL

logger = logging.getLogger(__name__)

# RIL socket configuration
RIL_SOCKET_HOST = "0.0.0.0"
RIL_SOCKET_PORT = 18000  # Custom port for virtual RIL


class RILRequest(IntEnum):
    """RIL request IDs (from ril.h)."""
    GET_SIM_STATUS = 1
    ENTER_SIM_PIN = 2
    GET_CURRENT_CALLS = 9
    DIAL = 10
    GET_IMSI = 11
    HANGUP = 12
    SIGNAL_STRENGTH = 19
    VOICE_REG_STATE = 20
    DATA_REG_STATE = 21
    OPERATOR = 22
    RADIO_POWER = 23
    SEND_SMS = 25
    SEND_SMS_EXPECT_MORE = 26
    SIM_IO = 28
    GET_IMEI = 38
    ANSWER = 40
    DATA_CALL_LIST = 57
    SET_INITIAL_ATTACH_APN = 111
    SIM_AUTHENTICATION = 125
    SET_DATA_PROFILE = 128


class RILUnsol(IntEnum):
    """RIL unsolicited indication IDs."""
    RADIO_STATE_CHANGED = 1000
    NETWORK_STATE_CHANGED = 1001
    CALL_RING = 1002
    NEW_SMS = 1003
    NITZ_TIME_RECEIVED = 1008
    SIM_STATUS_CHANGED = 1019


class RILResponse(IntEnum):
    """RIL response types."""
    SOLICITED = 0
    UNSOLICITED = 1


@dataclass
class RILMessage:
    """A RIL wire-format message."""
    msg_type: int  # 0=solicited, 1=unsolicited
    serial: int    # Request serial number
    request_id: int
    data: dict

    def serialize(self) -> bytes:
        """Serialize to RIL wire format (length-prefixed JSON)."""
        payload = json.dumps({
            "type": self.msg_type,
            "serial": self.serial,
            "id": self.request_id,
            "data": self.data,
        }).encode()
        return struct.pack("!I", len(payload)) + payload

    @classmethod
    def deserialize(cls, raw: bytes) -> RILMessage:
        """Deserialize from wire format."""
        msg = json.loads(raw)
        return cls(
            msg_type=msg.get("type", 0),
            serial=msg.get("serial", 0),
            request_id=msg.get("id", 0),
            data=msg.get("data", {}),
        )


class RILBridge:
    """
    RIL Bridge server.

    Accepts connections from the C RIL shim (inside redroid)
    and forwards requests to the virtual RadioHAL.
    """

    def __init__(
        self,
        host: str = RIL_SOCKET_HOST,
        port: int = RIL_SOCKET_PORT,
    ):
        self.host = host
        self.port = port
        self.radio_hal = RadioHAL()
        self._server: Optional[asyncio.AbstractServer] = None
        self._clients: list[asyncio.StreamWriter] = []

    async def start(self) -> None:
        """Start the RIL bridge server."""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        # Wire up unsolicited indication callback
        self.radio_hal.set_indication_callback(self._broadcast_unsolicited)
        await self.radio_hal.power_on()
        logger.info("RIL bridge listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the RIL bridge server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        await self.radio_hal.power_off()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a connected RIL client (C shim)."""
        addr = writer.get_extra_info("peername")
        logger.info("RIL client connected: %s", addr)
        self._clients.append(writer)

        # Send initial unsolicited radio state indication
        await self._send_unsolicited(
            writer, RILUnsol.RADIO_STATE_CHANGED,
            {"radioState": self.radio_hal.radio_state.value},
        )

        try:
            while True:
                # Read length-prefixed message
                length_bytes = await reader.readexactly(4)
                length = struct.unpack("!I", length_bytes)[0]

                if length > 1024 * 1024:
                    logger.warning("RIL message too large: %d", length)
                    break

                msg_bytes = await reader.readexactly(length)
                msg = RILMessage.deserialize(msg_bytes)

                # Process the request
                response = await self._process_request(msg)

                # Send response
                writer.write(response.serialize())
                await writer.drain()

        except asyncio.IncompleteReadError:
            logger.info("RIL client disconnected: %s", addr)
        except Exception:
            logger.exception("RIL bridge error for %s", addr)
        finally:
            self._clients.remove(writer)
            writer.close()
            await writer.wait_closed()

    async def _process_request(self, msg: RILMessage) -> RILMessage:
        """Process a RIL request and return a response."""
        request_id = msg.request_id
        serial = msg.serial

        handlers = {
            RILRequest.GET_SIM_STATUS: self._handle_get_sim_status,
            RILRequest.GET_IMSI: self._handle_get_imsi,
            RILRequest.GET_IMEI: self._handle_get_imei,
            RILRequest.OPERATOR: self._handle_get_operator,
            RILRequest.SIGNAL_STRENGTH: self._handle_signal_strength,
            RILRequest.VOICE_REG_STATE: self._handle_voice_reg,
            RILRequest.DATA_REG_STATE: self._handle_data_reg,
            RILRequest.RADIO_POWER: self._handle_radio_power,
            RILRequest.SIM_IO: self._handle_sim_io,
            RILRequest.SIM_AUTHENTICATION: self._handle_sim_auth,
            RILRequest.SEND_SMS: self._handle_send_sms,
            RILRequest.SEND_SMS_EXPECT_MORE: self._handle_send_sms,
            RILRequest.ENTER_SIM_PIN: self._handle_enter_pin,
            RILRequest.DATA_CALL_LIST: self._handle_data_call_list,
            RILRequest.SET_INITIAL_ATTACH_APN: self._handle_set_initial_attach_apn,
            RILRequest.SET_DATA_PROFILE: self._handle_set_data_profile,
            RILRequest.GET_CURRENT_CALLS: self._handle_get_current_calls,
            RILRequest.DIAL: self._handle_dial,
            RILRequest.HANGUP: self._handle_hangup,
            RILRequest.ANSWER: self._handle_answer,
        }

        handler = handlers.get(request_id)
        if handler:
            data = await handler(msg.data)
        else:
            logger.debug("Unhandled RIL request: %d", request_id)
            data = {"error": "REQUEST_NOT_SUPPORTED"}

        return RILMessage(
            msg_type=RILResponse.SOLICITED,
            serial=serial,
            request_id=request_id,
            data=data,
        )

    # -- Request handlers --

    async def _handle_get_sim_status(self, data: dict) -> dict:
        return await self.radio_hal.get_sim_status()

    async def _handle_get_imsi(self, data: dict) -> dict:
        imsi = await self.radio_hal.get_imsi()
        return {"imsi": imsi}

    async def _handle_get_imei(self, data: dict) -> dict:
        imei = await self.radio_hal.get_imei()
        return {"imei": imei}

    async def _handle_get_operator(self, data: dict) -> dict:
        return await self.radio_hal.get_operator()

    async def _handle_signal_strength(self, data: dict) -> dict:
        return await self.radio_hal.get_signal_strength()

    async def _handle_voice_reg(self, data: dict) -> dict:
        return await self.radio_hal.get_voice_registration_state()

    async def _handle_data_reg(self, data: dict) -> dict:
        return await self.radio_hal.get_data_registration_state()

    async def _handle_radio_power(self, data: dict) -> dict:
        on = data.get("on", True)
        await self.radio_hal.set_radio_power(on)
        return {"success": True}

    async def _handle_sim_io(self, data: dict) -> dict:
        return await self.radio_hal.sim_io(
            command=data.get("command", 0),
            file_id=data.get("fileId", 0),
            path=data.get("path", ""),
            p1=data.get("p1", 0),
            p2=data.get("p2", 0),
            p3=data.get("p3", 0),
            data=data.get("data", ""),
            pin2=data.get("pin2", ""),
            aid=data.get("aid", ""),
        )

    async def _handle_sim_auth(self, data: dict) -> dict:
        context = data.get("authContext", 0)
        auth_data = data.get("authData", "")
        return await self.radio_hal.sim_authentication(context, auth_data)

    async def _handle_send_sms(self, data: dict) -> dict:
        return await self.radio_hal.send_sms(
            smsc_pdu=data.get("smscPdu", ""),
            pdu=data.get("pdu", ""),
        )

    async def _handle_enter_pin(self, data: dict) -> dict:
        pin = data.get("pin", "")
        return await self.radio_hal.supply_icc_pin(pin)

    async def _handle_data_call_list(self, data: dict) -> dict:
        return await self.radio_hal.get_data_call_list()

    async def _handle_set_initial_attach_apn(self, data: dict) -> dict:
        return await self.radio_hal.set_initial_attach_apn(data)

    async def _handle_set_data_profile(self, data: dict) -> dict:
        return await self.radio_hal.set_data_profile(data)

    async def _handle_get_current_calls(self, data: dict) -> dict:
        return await self.radio_hal.get_current_calls()

    async def _handle_dial(self, data: dict) -> dict:
        number = data.get("address", "")
        clir = data.get("clir", 0)
        return await self.radio_hal.dial(number, clir)

    async def _handle_hangup(self, data: dict) -> dict:
        call_index = data.get("callIndex", data.get("gsmIndex", 1))
        return await self.radio_hal.hangup(call_index)

    async def _handle_answer(self, data: dict) -> dict:
        return await self.radio_hal.answer()

    # -- Unsolicited indications --

    async def _broadcast_unsolicited(
        self, indication_id: int, data: dict
    ) -> None:
        """Broadcast an unsolicited indication to all connected clients."""
        for writer in list(self._clients):
            try:
                await self._send_unsolicited(writer, indication_id, data)
            except Exception:
                logger.debug("Failed to send unsolicited to client")

    async def _send_unsolicited(
        self,
        writer: asyncio.StreamWriter,
        indication_id: int,
        data: dict,
    ) -> None:
        """Send an unsolicited RIL indication."""
        msg = RILMessage(
            msg_type=RILResponse.UNSOLICITED,
            serial=0,
            request_id=indication_id,
            data=data,
        )
        writer.write(msg.serialize())
        await writer.drain()
