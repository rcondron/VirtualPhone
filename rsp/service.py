"""
RSP service - runs the LPA as a background service.

Listens for profile download requests and manages RSP sessions.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal

from rsp.lpa import LPA

logging.basicConfig(
    level=getattr(logging, os.environ.get("VPHONE_LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("rsp.service")

RSP_SOCKET = "/run/vphone/rsp.sock"


async def handle_client(
    lpa: LPA,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    """Handle a client connection to the RSP service."""
    try:
        while True:
            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, "big")
            msg_bytes = await reader.readexactly(length)
            msg = json.loads(msg_bytes)

            cmd = msg.get("command")
            result = {}

            if cmd == "download":
                result = await lpa.download_profile(
                    activation_code=msg.get("activation_code", ""),
                    confirmation_code=msg.get("confirmation_code"),
                )
            elif cmd == "install_direct":
                result = await lpa.install_profile_direct(msg.get("profile", {}))
            elif cmd == "list":
                result = {"profiles": await lpa.list_profiles()}
            elif cmd == "enable":
                ok = await lpa.enable_profile(msg.get("iccid", ""))
                result = {"success": ok}
            elif cmd == "disable":
                ok = await lpa.disable_profile(msg.get("iccid", ""))
                result = {"success": ok}
            elif cmd == "delete":
                ok = await lpa.delete_profile(msg.get("iccid", ""))
                result = {"success": ok}
            elif cmd == "info":
                result = await lpa.get_euicc_info()
            elif cmd == "eid":
                result = {"eid": await lpa.get_eid()}
            else:
                result = {"error": f"Unknown command: {cmd}"}

            resp_bytes = json.dumps(result).encode()
            writer.write(len(resp_bytes).to_bytes(4, "big"))
            writer.write(resp_bytes)
            await writer.drain()

    except asyncio.IncompleteReadError:
        pass
    except Exception:
        logger.exception("RSP client error")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    lpa = LPA(
        smdp_address=os.environ.get("VPHONE_RSP_SERVER", ""),
    )

    # Wait for eUICC daemon to be ready
    for i in range(30):
        try:
            await lpa.initialize()
            break
        except Exception:
            if i == 29:
                logger.error("Could not connect to eUICC daemon")
                return
            await asyncio.sleep(2)

    # Start RSP service socket
    if os.path.exists(RSP_SOCKET):
        os.unlink(RSP_SOCKET)

    server = await asyncio.start_unix_server(
        lambda r, w: handle_client(lpa, r, w),
        path=RSP_SOCKET,
    )
    os.chmod(RSP_SOCKET, 0o660)

    logger.info("RSP service listening on %s", RSP_SOCKET)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: loop.stop())
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
