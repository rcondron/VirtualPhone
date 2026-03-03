"""
PSTN SMS bridge via Twilio or Telnyx.

Provides a webhook endpoint for receiving SMS from the PSTN, and an API
for sending SMS to PSTN numbers via a provider (Twilio or Telnyx).

When a PSTN SMS arrives, it is delivered to Android as an MT-SMS via
the SMSoverIMS → RadioHAL → RIL path.

When Android sends an SMS to a PSTN number, the SMSoverIMS module
calls this bridge to deliver via the configured provider.

Configuration via environment variables:
  VPHONE_SMS_PROVIDER=twilio|telnyx
  VPHONE_SMS_ACCOUNT_SID=...     (Twilio)
  VPHONE_SMS_AUTH_TOKEN=...      (Twilio)
  VPHONE_SMS_FROM_NUMBER=+1...   (PSTN number to send from)
  VPHONE_SMS_TELNYX_API_KEY=...  (Telnyx)

Reference: Twilio SMS API, Telnyx Messaging API
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable

import httpx

logger = logging.getLogger(__name__)


@dataclass
class PSTNBridgeConfig:
    """PSTN SMS bridge configuration."""
    provider: str = ""          # "twilio" or "telnyx"
    from_number: str = ""       # E.164 PSTN number
    # Twilio
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    # Telnyx
    telnyx_api_key: str = ""
    # Webhook
    webhook_port: int = 8444

    @classmethod
    def from_env(cls) -> PSTNBridgeConfig:
        """Load configuration from environment variables."""
        return cls(
            provider=os.environ.get("VPHONE_SMS_PROVIDER", ""),
            from_number=os.environ.get("VPHONE_SMS_FROM_NUMBER", ""),
            twilio_account_sid=os.environ.get("VPHONE_SMS_ACCOUNT_SID", ""),
            twilio_auth_token=os.environ.get("VPHONE_SMS_AUTH_TOKEN", ""),
            telnyx_api_key=os.environ.get("VPHONE_SMS_TELNYX_API_KEY", ""),
            webhook_port=int(os.environ.get("VPHONE_SMS_WEBHOOK_PORT", "8444")),
        )


class PSTNBridge:
    """
    PSTN SMS bridge.

    Routes SMS between the IMS network and the PSTN via Twilio or Telnyx.
    """

    def __init__(self, config: PSTNBridgeConfig):
        self.config = config
        self._mt_callback: Optional[Callable[[str, str], Awaitable[None]]] = None
        self._http_client: Optional[httpx.AsyncClient] = None
        self._webhook_server: Optional[asyncio.AbstractServer] = None

    @property
    def enabled(self) -> bool:
        return bool(self.config.provider and self.config.from_number)

    def set_mt_callback(self, cb: Callable[[str, str], Awaitable[None]]) -> None:
        """
        Set callback for incoming PSTN SMS.

        Callback args: (from_number, text)
        """
        self._mt_callback = cb

    async def start(self) -> None:
        """Start the PSTN bridge (HTTP client + webhook server)."""
        if not self.enabled:
            logger.info("PSTN bridge: not configured, skipping")
            return

        self._http_client = httpx.AsyncClient(timeout=30.0)

        # Start webhook server for incoming SMS
        from aiohttp import web

        app = web.Application()
        app.router.add_post("/sms/incoming", self._webhook_handler)
        app.router.add_get("/sms/health", self._health_handler)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.config.webhook_port)
        await site.start()

        logger.info("PSTN bridge started: provider=%s, from=%s, webhook=:%d",
                     self.config.provider, self.config.from_number,
                     self.config.webhook_port)

    async def stop(self) -> None:
        """Stop the PSTN bridge."""
        if self._http_client:
            await self._http_client.aclose()

    async def send_sms(self, to_number: str, text: str) -> bool:
        """
        Send an SMS to a PSTN number via the configured provider.

        Args:
            to_number: E.164 destination number (e.g., "+14155551234")
            text: Message text

        Returns:
            True if the message was accepted by the provider.
        """
        if not self.enabled:
            logger.warning("PSTN bridge: not configured, cannot send")
            return False

        if self.config.provider == "twilio":
            return await self._send_twilio(to_number, text)
        elif self.config.provider == "telnyx":
            return await self._send_telnyx(to_number, text)
        else:
            logger.error("PSTN bridge: unknown provider '%s'", self.config.provider)
            return False

    async def _send_twilio(self, to_number: str, text: str) -> bool:
        """Send SMS via Twilio REST API."""
        url = (
            f"https://api.twilio.com/2010-04-01/Accounts/"
            f"{self.config.twilio_account_sid}/Messages.json"
        )

        try:
            resp = await self._http_client.post(
                url,
                auth=(self.config.twilio_account_sid, self.config.twilio_auth_token),
                data={
                    "From": self.config.from_number,
                    "To": to_number,
                    "Body": text,
                },
            )

            if resp.status_code == 201:
                sid = resp.json().get("sid", "")
                logger.info("PSTN→Twilio: sent to=%s sid=%s", to_number, sid)
                return True
            else:
                logger.error("PSTN→Twilio: failed %d: %s",
                             resp.status_code, resp.text[:200])
                return False

        except Exception:
            logger.exception("PSTN→Twilio: request failed")
            return False

    async def _send_telnyx(self, to_number: str, text: str) -> bool:
        """Send SMS via Telnyx Messaging API."""
        url = "https://api.telnyx.com/v2/messages"

        try:
            resp = await self._http_client.post(
                url,
                headers={
                    "Authorization": f"Bearer {self.config.telnyx_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": self.config.from_number,
                    "to": to_number,
                    "text": text,
                },
            )

            if resp.status_code in (200, 201):
                msg_id = resp.json().get("data", {}).get("id", "")
                logger.info("PSTN→Telnyx: sent to=%s id=%s", to_number, msg_id)
                return True
            else:
                logger.error("PSTN→Telnyx: failed %d: %s",
                             resp.status_code, resp.text[:200])
                return False

        except Exception:
            logger.exception("PSTN→Telnyx: request failed")
            return False

    async def _webhook_handler(self, request) -> "web.Response":
        """Handle incoming SMS webhooks from Twilio or Telnyx."""
        from aiohttp import web

        try:
            if self.config.provider == "twilio":
                data = await request.post()
                from_number = data.get("From", "")
                text = data.get("Body", "")
            elif self.config.provider == "telnyx":
                data = await request.json()
                payload = data.get("data", {}).get("payload", {})
                from_number = payload.get("from", {}).get("phone_number", "")
                text = payload.get("text", "")
            else:
                return web.Response(status=400, text="Unknown provider")

            logger.info("PSTN←webhook: from=%s text='%s'", from_number, text[:50])

            if self._mt_callback and from_number and text:
                await self._mt_callback(from_number, text)

            # Twilio expects TwiML, Telnyx expects 200
            if self.config.provider == "twilio":
                return web.Response(
                    text='<?xml version="1.0" encoding="UTF-8"?><Response></Response>',
                    content_type="application/xml",
                )
            return web.Response(status=200)

        except Exception:
            logger.exception("PSTN webhook error")
            return web.Response(status=500)

    async def _health_handler(self, request) -> "web.Response":
        """Health check for the webhook server."""
        from aiohttp import web
        return web.json_response({
            "status": "ok",
            "provider": self.config.provider,
            "from": self.config.from_number,
        })
