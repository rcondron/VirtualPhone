"""
eUICC daemon - main entry point for the virtual eUICC service.

Runs as a background service that:
1. Initializes the virtual eUICC
2. Listens on a Unix socket for APDU commands from the RIL bridge
3. Processes commands and returns responses
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys

from euicc.euicc import VirtualEUICC
from euicc.apdu.handler import APDUHandler

logging.basicConfig(
    level=getattr(logging, os.environ.get("VPHONE_LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("euicc.daemon")

SOCKET_PATH = "/run/vphone/euicc.sock"


class EUICCDaemon:
    """Async daemon that serves APDU commands over a Unix socket."""

    def __init__(self):
        self.euicc = VirtualEUICC(
            profile_dir=os.environ.get("VPHONE_PROFILE_DIR", "/var/lib/vphone/profiles"),
            key_dir=os.environ.get("VPHONE_KEY_DIR", "/var/lib/vphone/keys"),
        )
        self.apdu_handler = APDUHandler(self.euicc)
        self._server: asyncio.AbstractServer | None = None

    async def start(self):
        """Initialize the eUICC and start the APDU socket server."""
        logger.info("Starting eUICC daemon...")
        self.euicc.initialize()

        # Remove stale socket file
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=SOCKET_PATH
        )
        os.chmod(SOCKET_PATH, 0o660)

        logger.info("eUICC daemon listening on %s", SOCKET_PATH)

        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a connected client (RIL bridge or management tool)."""
        peer = "unix-client"
        logger.debug("Client connected: %s", peer)

        try:
            while True:
                # Protocol: 4-byte length prefix (big-endian) + JSON message
                length_bytes = await reader.readexactly(4)
                length = int.from_bytes(length_bytes, "big")

                if length > 65536:
                    logger.warning("Message too large (%d bytes), dropping", length)
                    break

                msg_bytes = await reader.readexactly(length)
                msg = json.loads(msg_bytes)

                response = await self._process_message(msg)

                resp_bytes = json.dumps(response).encode()
                writer.write(len(resp_bytes).to_bytes(4, "big"))
                writer.write(resp_bytes)
                await writer.drain()

        except asyncio.IncompleteReadError:
            logger.debug("Client disconnected: %s", peer)
        except Exception:
            logger.exception("Error handling client %s", peer)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _process_message(self, msg: dict) -> dict:
        """Process a message from the RIL bridge."""
        msg_type = msg.get("type")

        if msg_type == "apdu":
            # Raw APDU command
            apdu_hex = msg.get("data", "")
            apdu_bytes = bytes.fromhex(apdu_hex)
            response = self.apdu_handler.process(apdu_bytes)
            return {
                "type": "apdu_response",
                "data": response.to_bytes().hex(),
                "sw": response.status_word,
            }

        elif msg_type == "get_info":
            return {"type": "info", "data": self.euicc.get_euicc_info()}

        elif msg_type == "list_profiles":
            return {"type": "profiles", "data": self.euicc.list_profiles()}

        elif msg_type == "enable_profile":
            iccid = msg.get("iccid", "")
            ok = self.euicc.enable_profile(iccid)
            return {"type": "result", "success": ok}

        elif msg_type == "disable_profile":
            iccid = msg.get("iccid", "")
            ok = self.euicc.disable_profile(iccid)
            return {"type": "result", "success": ok}

        elif msg_type == "install_profile":
            profile_data = msg.get("profile", {})
            isdp = self.euicc.install_profile(profile_data)
            return {"type": "result", "success": True, "iccid": isdp.iccid}

        elif msg_type == "delete_profile":
            iccid = msg.get("iccid", "")
            ok = self.euicc.delete_profile(iccid)
            return {"type": "result", "success": ok}

        elif msg_type == "get_profile_credentials":
            iccid = msg.get("iccid", "")
            profile = self.euicc.profiles.get(iccid)
            if profile is None:
                return {"type": "error", "message": f"Profile {iccid} not found"}
            usim = profile.get_usim_data()
            isim = profile.get_isim_data()
            return {
                "type": "credentials",
                "data": {**usim, **(isim or {})},
            }

        else:
            return {"type": "error", "message": f"Unknown message type: {msg_type}"}


def main():
    daemon = EUICCDaemon()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Graceful shutdown
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: loop.stop())

    try:
        loop.run_until_complete(daemon.start())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
        logger.info("eUICC daemon stopped.")


if __name__ == "__main__":
    main()
