"""Entry point for `python -m hal`."""
from hal.service import main

import asyncio
import signal

loop = asyncio.new_event_loop()
for sig in (signal.SIGTERM, signal.SIGINT):
    loop.add_signal_handler(sig, lambda: loop.stop())
try:
    loop.run_until_complete(main())
except KeyboardInterrupt:
    pass
finally:
    loop.close()
