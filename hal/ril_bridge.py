"""
RIL (Radio Interface Layer) bridge.

Bridges the Android RIL running inside redroid to the virtual eUICC
and telecom stack running on the host. Communication happens over
a TCP socket that emulates the RIL daemon socket.

The bridge:
1. Listens for RIL solicited/unsolicited requests from Android
2. Translates them into commands for the virtual eUICC
3. Sends responses back in the RIL wire format

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
    GET_IMSI = 11
    DIAL = 10
    GET_CURRENT_CALLS = 9
    HANGUP = 12
    ANSWER = 40
    SIGNAL_STRENGTH = 19
    VOICE_REG_STATE = 20
    DATA_REG_STATE = 21
    OPERATOR = 22
    RADIO_POWER = 23
    SEND_SMS = 25
    SEND_SMS_EXPECT_MORE = 26
    SIM_IO = 28
    GET_IMEI = 38
    SIM_AUTHENTICATION = 125
    SET_INITIAL_ATTACH_APN = 111
    DATA_CALL_LIST = 57
    SET_DATA_PROFILE = 128
    GET_ICC_CARD_STATUS = 1


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
        """Serialize to RIL wire format (simplified JSON-based)."""
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

    Accepts connections from Android's RIL daemon (inside redroid)
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

    async def start(self) -> None:
        """Start the RIL bridge server."""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
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
        """Handle a connected RIL client."""
        addr = writer.get_extra_info("peername")
        logger.info("RIL client connected: %s", addr)

        # Send initial unsolicited radio state indication
        await self._send_unsolicited(
            writer, 1000,  # RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED
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
            writer.close()
            await writer.wait_closed()

    async def _process_request(self, msg: RILMessage) -> RILMessage:
        """Process a RIL request and return a response."""
        request_id = msg.request_id
        serial = msg.serial

        handlers = {
            RILRequest.GET_SIM_STATUS: self._handle_get_sim_status,
            RILRequest.GET_IMSI: self._handle_get_imsi,
            RILRequest.OPERATOR: self._handle_get_operator,
            RILRequest.SIGNAL_STRENGTH: self._handle_signal_strength,
            RILRequest.VOICE_REG_STATE: self._handle_voice_reg,
            RILRequest.DATA_REG_STATE: self._handle_data_reg,
            RILRequest.RADIO_POWER: self._handle_radio_power,
            RILRequest.SIM_AUTHENTICATION: self._handle_sim_auth,
            RILRequest.ENTER_SIM_PIN: self._handle_enter_pin,
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

    async def _handle_get_sim_status(self, data: dict) -> dict:
        return await self.radio_hal.get_sim_status()

    async def _handle_get_imsi(self, data: dict) -> dict:
        imsi = await self.radio_hal.get_imsi()
        return {"imsi": imsi}

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

    async def _handle_sim_auth(self, data: dict) -> dict:
        context = data.get("authContext", 0)
        auth_data = data.get("authData", "")
        return await self.radio_hal.sim_authentication(context, auth_data)

    async def _handle_enter_pin(self, data: dict) -> dict:
        pin = data.get("pin", "")
        return await self.radio_hal.supply_icc_pin(pin)

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
