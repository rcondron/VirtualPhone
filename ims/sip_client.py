"""
SIP (Session Initiation Protocol) client for IMS.

Implements core SIP functionality needed for IMS registration:
- SIP message parsing and construction (RFC 3261)
- SIP digest authentication (RFC 2617)
- SIP over TCP/TLS/UDP
- Transaction management

Reference: RFC 3261 (SIP), RFC 3329 (Security Mechanism Agreement),
           3GPP TS 24.229 (IMS SIP procedures)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable, Awaitable

logger = logging.getLogger(__name__)


class SIPMethod(str):
    """SIP request methods."""
    REGISTER = "REGISTER"
    INVITE = "INVITE"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    OPTIONS = "OPTIONS"
    SUBSCRIBE = "SUBSCRIBE"
    NOTIFY = "NOTIFY"
    MESSAGE = "MESSAGE"


class SIPStatus(IntEnum):
    """Common SIP response status codes."""
    TRYING = 100
    RINGING = 180
    OK = 200
    UNAUTHORIZED = 401
    PROXY_AUTH_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    TEMPORARILY_UNAVAILABLE = 480
    SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503


@dataclass
class SIPHeader:
    """A SIP header key-value pair."""
    name: str
    value: str


@dataclass
class SIPMessage:
    """A parsed SIP message (request or response)."""
    # Request line (for requests)
    method: Optional[str] = None
    request_uri: Optional[str] = None

    # Status line (for responses)
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None

    # Common
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def is_request(self) -> bool:
        return self.method is not None

    @property
    def is_response(self) -> bool:
        return self.status_code is not None

    @property
    def call_id(self) -> str:
        return self.headers.get("Call-ID", "")

    @property
    def cseq(self) -> str:
        return self.headers.get("CSeq", "")

    @property
    def from_header(self) -> str:
        return self.headers.get("From", "")

    @property
    def to_header(self) -> str:
        return self.headers.get("To", "")

    @classmethod
    def parse(cls, data: bytes) -> SIPMessage:
        """Parse a SIP message from raw bytes."""
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        if not lines:
            raise ValueError("Empty SIP message")

        msg = cls()

        # Parse first line (request-line or status-line)
        first_line = lines[0]
        if first_line.startswith("SIP/2.0"):
            # Status line: SIP/2.0 <code> <reason>
            parts = first_line.split(" ", 2)
            msg.status_code = int(parts[1])
            msg.reason_phrase = parts[2] if len(parts) > 2 else ""
        else:
            # Request line: <method> <uri> SIP/2.0
            parts = first_line.split(" ", 2)
            msg.method = parts[0]
            msg.request_uri = parts[1] if len(parts) > 1 else ""

        # Parse headers
        i = 1
        while i < len(lines) and lines[i]:
            if ":" in lines[i]:
                name, value = lines[i].split(":", 1)
                msg.headers[name.strip()] = value.strip()
            i += 1

        # Parse body (after blank line)
        if i + 1 < len(lines):
            msg.body = "\r\n".join(lines[i + 1:]).encode()

        return msg

    def serialize(self) -> bytes:
        """Serialize to bytes for transmission."""
        lines = []

        if self.is_request:
            lines.append(f"{self.method} {self.request_uri} SIP/2.0")
        else:
            lines.append(f"SIP/2.0 {self.status_code} {self.reason_phrase}")

        # Add Content-Length if body present
        if self.body:
            self.headers["Content-Length"] = str(len(self.body))
        elif "Content-Length" not in self.headers:
            self.headers["Content-Length"] = "0"

        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")

        lines.append("")  # blank line before body

        result = "\r\n".join(lines).encode()
        if self.body:
            result += b"\r\n" + self.body

        return result


def generate_call_id() -> str:
    """Generate a unique Call-ID."""
    return f"{os.urandom(8).hex()}@virtualphone"


def generate_branch() -> str:
    """Generate a Via branch parameter (RFC 3261 magic cookie + random)."""
    return f"z9hG4bK{os.urandom(8).hex()}"


def generate_tag() -> str:
    """Generate a From/To tag."""
    return os.urandom(6).hex()


class SIPTransport:
    """
    SIP transport layer supporting UDP, TCP, and TLS.
    """

    def __init__(
        self,
        local_ip: str = "0.0.0.0",
        local_port: int = 5060,
        transport: str = "UDP",
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.transport = transport.upper()
        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_connections: dict[str, asyncio.StreamWriter] = {}
        self._message_handler: Optional[Callable[[SIPMessage, tuple], Awaitable[None]]] = None

    def set_handler(self, handler: Callable[[SIPMessage, tuple], Awaitable[None]]):
        """Set the callback for received SIP messages."""
        self._message_handler = handler

    async def start(self) -> None:
        """Start the SIP transport."""
        if self.transport == "UDP":
            loop = asyncio.get_event_loop()

            class SIPProtocol(asyncio.DatagramProtocol):
                def __init__(self, handler):
                    self.handler = handler

                def datagram_received(self, data, addr):
                    try:
                        msg = SIPMessage.parse(data)
                        if self.handler:
                            asyncio.ensure_future(self.handler(msg, addr))
                    except Exception as e:
                        logger.error("Failed to parse SIP message: %s", e)

            transport, _ = await loop.create_datagram_endpoint(
                lambda: SIPProtocol(self._message_handler),
                local_addr=(self.local_ip, self.local_port),
            )
            self._udp_transport = transport
            logger.info("SIP UDP transport started on %s:%d", self.local_ip, self.local_port)

    async def send(self, msg: SIPMessage, dest: tuple[str, int]) -> None:
        """Send a SIP message to a destination."""
        data = msg.serialize()

        if self.transport == "UDP":
            if self._udp_transport:
                self._udp_transport.sendto(data, dest)
        elif self.transport == "TCP":
            key = f"{dest[0]}:{dest[1]}"
            if key not in self._tcp_connections:
                reader, writer = await asyncio.open_connection(dest[0], dest[1])
                self._tcp_connections[key] = writer
            self._tcp_connections[key].write(data)
            await self._tcp_connections[key].drain()

    async def stop(self) -> None:
        """Stop the SIP transport."""
        if self._udp_transport:
            self._udp_transport.close()
        for writer in self._tcp_connections.values():
            writer.close()
        self._tcp_connections.clear()


class SIPClient:
    """
    SIP User Agent Client for IMS.

    Handles SIP transaction management, authentication, and
    message construction for IMS procedures.
    """

    def __init__(
        self,
        local_ip: str = "0.0.0.0",
        local_port: int = 5060,
        transport: str = "UDP",
    ):
        self.transport = SIPTransport(local_ip, local_port, transport)
        self.local_ip = local_ip
        self.local_port = local_port
        self._cseq = 1
        self._pending_responses: dict[str, asyncio.Future] = {}

    async def start(self) -> None:
        self.transport.set_handler(self._handle_message)
        await self.transport.start()

    async def stop(self) -> None:
        await self.transport.stop()

    async def send_request(
        self,
        method: str,
        request_uri: str,
        to_uri: str,
        from_uri: str,
        dest: tuple[str, int],
        extra_headers: Optional[dict[str, str]] = None,
        body: bytes = b"",
        call_id: Optional[str] = None,
    ) -> SIPMessage:
        """
        Send a SIP request and wait for the final response.

        Returns the final response (2xx, 4xx, 5xx, 6xx).
        """
        cid = call_id or generate_call_id()
        branch = generate_branch()
        tag = generate_tag()

        headers = {
            "Via": f"SIP/2.0/{self.transport.transport} {self.local_ip}:{self.local_port};branch={branch}",
            "Max-Forwards": "70",
            "From": f"<{from_uri}>;tag={tag}",
            "To": f"<{to_uri}>",
            "Call-ID": cid,
            "CSeq": f"{self._cseq} {method}",
            "User-Agent": "VirtualPhone/1.0",
        }

        if extra_headers:
            headers.update(extra_headers)

        msg = SIPMessage(
            method=method,
            request_uri=request_uri,
            headers=headers,
            body=body,
        )

        self._cseq += 1

        # Create a future to wait for the response
        future = asyncio.get_event_loop().create_future()
        self._pending_responses[cid] = future

        await self.transport.send(msg, dest)

        try:
            response = await asyncio.wait_for(future, timeout=32.0)
            return response
        except asyncio.TimeoutError:
            del self._pending_responses[cid]
            raise TimeoutError(f"SIP {method} timed out")

    async def _handle_message(self, msg: SIPMessage, addr: tuple) -> None:
        """Handle an incoming SIP message."""
        if msg.is_response:
            cid = msg.call_id
            if cid in self._pending_responses:
                # Only resolve for final responses (>= 200)
                if msg.status_code >= 200:
                    future = self._pending_responses.pop(cid)
                    if not future.done():
                        future.set_result(msg)
                else:
                    logger.debug("Provisional response %d for %s", msg.status_code, cid)

    def build_auth_header(
        self,
        www_authenticate: str,
        method: str,
        uri: str,
        username: str,
        password: str,
        nc: int = 1,
    ) -> str:
        """
        Build an Authorization header for SIP Digest authentication.

        Args:
            www_authenticate: The WWW-Authenticate header from a 401 response.
            method: SIP method (e.g., REGISTER).
            uri: Request URI.
            username: Authentication username (IMPI for IMS).
            password: Authentication password (derived from AKA).
        """
        # Parse WWW-Authenticate parameters
        params = {}
        for part in www_authenticate.replace("Digest ", "").split(","):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                params[key.strip()] = val.strip().strip('"')

        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        qop = params.get("qop", "auth")
        algorithm = params.get("algorithm", "MD5")

        cnonce = os.urandom(8).hex()
        nc_str = f"{nc:08x}"

        # Compute digest (RFC 2617)
        if algorithm.upper() == "AKAV1-MD5":
            # AKAv1-MD5 for IMS (3GPP TS 33.203)
            ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        else:
            ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()

        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

        if qop:
            response = hashlib.md5(
                f"{ha1}:{nonce}:{nc_str}:{cnonce}:{qop}:{ha2}".encode()
            ).hexdigest()
        else:
            response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        auth = (
            f'Digest username="{username}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", algorithm={algorithm}'
        )
        if qop:
            auth += f', qop={qop}, nc={nc_str}, cnonce="{cnonce}"'

        return auth
