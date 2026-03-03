"""
HAL service - runs the RIL bridge and eUICC HAL.

Starts the RIL bridge server that listens for connections from
Android's telephony stack inside redroid.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal

from hal.ril_bridge import RILBridge

logging.basicConfig(
    level=getattr(logging, os.environ.get("VPHONE_LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("hal.service")


async def main():
    logger.info("Starting HAL bridge service...")

    # Wait for eUICC daemon socket
    euicc_sock = "/run/vphone/euicc.sock"
    for i in range(30):
        if os.path.exists(euicc_sock):
            break
        await asyncio.sleep(2)

    bridge = RILBridge()
    await bridge.start()

    logger.info("HAL bridge service running")

    # Keep the service running
    try:
        while True:
            await asyncio.sleep(60)
    except asyncio.CancelledError:
        pass
    finally:
        await bridge.stop()


def run():
    """Synchronous entry point for the HAL bridge service."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: loop.stop())
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    run()
