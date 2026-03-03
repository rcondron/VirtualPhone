"""
Management REST API for the VirtualPhone environment.

Provides HTTP endpoints for:
- eUICC status and profile management
- Profile installation (direct and via RSP)
- IMS registration status
- VoWiFi tunnel status
- Health monitoring
- Prometheus metrics

Runs on port 9000 via uvicorn.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# =============================================================================
# Structured JSON logging
# =============================================================================

class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


def _setup_logging() -> None:
    """Configure structured JSON logging for all vphone loggers."""
    level = os.environ.get("VPHONE_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.setLevel(level)
    # Replace existing handlers
    root.handlers.clear()
    root.addHandler(handler)

    # Also write to file if the log directory exists
    log_dir = "/var/log/vphone"
    if os.path.isdir(log_dir):
        fh = logging.FileHandler(os.path.join(log_dir, "api.jsonl"))
        fh.setFormatter(JSONFormatter())
        root.addHandler(fh)


_setup_logging()


# =============================================================================
# Prometheus metrics
# =============================================================================

class Metrics:
    """Simple Prometheus metrics collector."""

    def __init__(self):
        self.request_count: dict[str, int] = {}
        self.request_latency_sum: dict[str, float] = {}
        self.request_errors: dict[str, int] = {}
        self.profile_installs = 0
        self.profile_deletes = 0

    def record_request(self, method: str, path: str, status: int, duration: float) -> None:
        key = f"{method} {path}"
        self.request_count[key] = self.request_count.get(key, 0) + 1
        self.request_latency_sum[key] = self.request_latency_sum.get(key, 0.0) + duration
        if status >= 400:
            self.request_errors[key] = self.request_errors.get(key, 0) + 1

    def render(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        lines: list[str] = []

        lines.append("# HELP vphone_http_requests_total Total HTTP requests")
        lines.append("# TYPE vphone_http_requests_total counter")
        for key, count in sorted(self.request_count.items()):
            method, path = key.split(" ", 1)
            lines.append(
                f'vphone_http_requests_total{{method="{method}",path="{path}"}} {count}'
            )

        lines.append("# HELP vphone_http_request_duration_seconds Total request duration")
        lines.append("# TYPE vphone_http_request_duration_seconds counter")
        for key, total in sorted(self.request_latency_sum.items()):
            method, path = key.split(" ", 1)
            lines.append(
                f'vphone_http_request_duration_seconds{{method="{method}",path="{path}"}} {total:.6f}'
            )

        lines.append("# HELP vphone_http_errors_total Total HTTP errors (4xx/5xx)")
        lines.append("# TYPE vphone_http_errors_total counter")
        for key, count in sorted(self.request_errors.items()):
            method, path = key.split(" ", 1)
            lines.append(
                f'vphone_http_errors_total{{method="{method}",path="{path}"}} {count}'
            )

        lines.append("# HELP vphone_profile_installs_total Total profile installs")
        lines.append("# TYPE vphone_profile_installs_total counter")
        lines.append(f"vphone_profile_installs_total {self.profile_installs}")

        lines.append("# HELP vphone_profile_deletes_total Total profile deletes")
        lines.append("# TYPE vphone_profile_deletes_total counter")
        lines.append(f"vphone_profile_deletes_total {self.profile_deletes}")

        return "\n".join(lines) + "\n"


metrics = Metrics()


# =============================================================================
# API Key Authentication
# =============================================================================

_API_KEY = os.environ.get("VPHONE_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Endpoints that don't require auth
_PUBLIC_PATHS = {"/health", "/metrics", "/openapi.json", "/docs", "/redoc"}


async def verify_api_key(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
) -> None:
    """Validate the API key if one is configured."""
    if not _API_KEY:
        return  # No key configured — open access
    if request.url.path in _PUBLIC_PATHS:
        return
    if not api_key or api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# =============================================================================
# FastAPI application
# =============================================================================

app = FastAPI(
    title="VirtualPhone Management API",
    description="Manage the virtual eUICC, eSIM profiles, and telecom services",
    version="1.0.0",
    dependencies=[Depends(verify_api_key)],
)

EUICC_SOCKET = "/run/vphone/euicc.sock"
RSP_SOCKET = "/run/vphone/rsp.sock"


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Record request metrics and add request-id logging."""
    start = time.monotonic()
    response: Response = await call_next(request)
    duration = time.monotonic() - start

    path = request.url.path
    # Normalize paths with path params
    if path.startswith("/profiles/") and path.count("/") == 2:
        path = "/profiles/{iccid}"

    metrics.record_request(request.method, path, response.status_code, duration)
    logger.info(
        "%s %s -> %d (%.3fs)",
        request.method, request.url.path, response.status_code, duration,
    )
    return response


# -- Request/Response models --------------------------------------------------

class ProfileInstallRequest(BaseModel):
    """Request body for direct profile installation."""
    iccid: str
    imsi: str
    ki: str
    opc: str
    mcc: str = "001"
    mnc: str = "01"
    spn: str = "Virtual Operator"
    msisdn: Optional[str] = None
    impi: Optional[str] = None
    impu: Optional[str] = None
    home_domain: Optional[str] = None


class ActivationCodeRequest(BaseModel):
    """Request body for RSP profile download."""
    activation_code: str
    confirmation_code: Optional[str] = None


class ProfileActionRequest(BaseModel):
    """Request body for profile enable/disable/delete."""
    iccid: str


# -- Socket communication helpers --------------------------------------------

async def _send_euicc(msg: dict) -> dict:
    """Send a message to the eUICC daemon."""
    return await _send_socket(EUICC_SOCKET, msg)


async def _send_rsp(msg: dict) -> dict:
    """Send a message to the RSP service."""
    return await _send_socket(RSP_SOCKET, msg)


async def _send_socket(path: str, msg: dict) -> dict:
    try:
        reader, writer = await asyncio.open_unix_connection(path)
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
        raise HTTPException(status_code=503, detail=f"Service unavailable: {e}")


# -- Health -------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint (no auth required)."""
    try:
        resp = await _send_euicc({"type": "get_info"})
        euicc_ok = "data" in resp
    except Exception:
        euicc_ok = False

    return {
        "status": "healthy" if euicc_ok else "degraded",
        "euicc": "ok" if euicc_ok else "unavailable",
    }


# -- Prometheus Metrics -------------------------------------------------------

@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint (no auth required)."""
    # Add profile count from eUICC if available
    try:
        resp = await _send_euicc({"type": "list_profiles"})
        profile_count = len(resp.get("data", []))
        enabled_count = sum(
            1 for p in resp.get("data", []) if p.get("state") == "enabled"
        )
    except Exception:
        profile_count = -1
        enabled_count = -1

    body = metrics.render()
    body += "# HELP vphone_profiles_installed Number of installed profiles\n"
    body += "# TYPE vphone_profiles_installed gauge\n"
    body += f"vphone_profiles_installed {profile_count}\n"
    body += "# HELP vphone_profiles_enabled Number of enabled profiles\n"
    body += "# TYPE vphone_profiles_enabled gauge\n"
    body += f"vphone_profiles_enabled {enabled_count}\n"

    return Response(content=body, media_type="text/plain; version=0.0.4")


# -- eUICC Information --------------------------------------------------------

@app.get("/euicc/info")
async def get_euicc_info():
    """Get eUICC information (EID, version, memory, etc.)."""
    resp = await _send_euicc({"type": "get_info"})
    return resp.get("data", {})


@app.get("/euicc/eid")
async def get_eid():
    """Get the eUICC EID."""
    resp = await _send_euicc({"type": "get_info"})
    return {"eid": resp.get("data", {}).get("eid", "")}


# -- Profile Management ------------------------------------------------------

@app.get("/profiles")
async def list_profiles():
    """List all installed eSIM profiles."""
    resp = await _send_euicc({"type": "list_profiles"})
    return {"profiles": resp.get("data", [])}


@app.post("/profiles/install")
async def install_profile(req: ProfileInstallRequest):
    """
    Install an eSIM profile directly (bypass RSP).

    For testing and development. Provide the profile credentials
    directly in the request body.
    """
    profile_data = req.model_dump(exclude_none=True)
    resp = await _send_euicc({
        "type": "install_profile",
        "profile": profile_data,
    })

    if resp.get("success"):
        metrics.profile_installs += 1
        return {
            "success": True,
            "iccid": resp.get("iccid"),
            "message": f"Profile {req.iccid} installed successfully",
        }
    raise HTTPException(status_code=400, detail=resp.get("message", "Install failed"))


@app.post("/profiles/download")
async def download_profile(req: ActivationCodeRequest):
    """
    Download and install a profile via RSP (SM-DP+).

    Initiates the full GSMA SGP.22 profile download flow.
    """
    resp = await _send_rsp({
        "command": "download",
        "activation_code": req.activation_code,
        "confirmation_code": req.confirmation_code,
    })
    return resp


@app.post("/profiles/enable")
async def enable_profile(req: ProfileActionRequest):
    """Enable an installed eSIM profile."""
    resp = await _send_euicc({
        "type": "enable_profile",
        "iccid": req.iccid,
    })
    if resp.get("success"):
        return {"success": True, "message": f"Profile {req.iccid} enabled"}
    raise HTTPException(status_code=400, detail="Failed to enable profile")


@app.post("/profiles/disable")
async def disable_profile(req: ProfileActionRequest):
    """Disable an installed eSIM profile."""
    resp = await _send_euicc({
        "type": "disable_profile",
        "iccid": req.iccid,
    })
    if resp.get("success"):
        return {"success": True, "message": f"Profile {req.iccid} disabled"}
    raise HTTPException(status_code=400, detail="Failed to disable profile")


@app.delete("/profiles/{iccid}")
async def delete_profile(iccid: str):
    """Delete an installed eSIM profile."""
    resp = await _send_euicc({
        "type": "delete_profile",
        "iccid": iccid,
    })
    if resp.get("success"):
        metrics.profile_deletes += 1
        return {"success": True, "message": f"Profile {iccid} deleted"}
    raise HTTPException(status_code=400, detail="Failed to delete profile")


# -- Telecom Status -----------------------------------------------------------

@app.get("/status/ims")
async def get_ims_status():
    """Get IMS registration status."""
    try:
        from ims.service import get_ims_state
        return get_ims_state()
    except ImportError:
        return {
            "registered": False,
            "state": "unavailable",
            "domain": os.environ.get("VPHONE_IMS_DOMAIN", ""),
            "pcscf": os.environ.get("VPHONE_IMS_PROXY", ""),
        }


@app.get("/status/vowifi")
async def get_vowifi_status():
    """Get VoWiFi tunnel status."""
    try:
        from ims.vowifi import get_vowifi_state
        return get_vowifi_state()
    except ImportError:
        return {
            "state": "unavailable",
            "tunnel_up": False,
            "epdg": os.environ.get("VPHONE_VOWIFI_EPDG", ""),
            "tunnel_ip": None,
            "pcscf_addresses": [],
            "dns_servers": [],
        }


@app.get("/status/sms")
async def get_sms_status():
    """Get SMS over IMS service status."""
    try:
        from ims.sms import get_sms_state
        return get_sms_state()
    except ImportError:
        return {
            "enabled": False,
            "messages_sent": 0,
            "messages_received": 0,
            "last_error": None,
        }


class SendSMSRequest(BaseModel):
    """Request body for sending an SMS via the management API."""
    to: str
    text: str


@app.post("/sms/send")
async def send_sms_api(req: SendSMSRequest):
    """
    Send an SMS message via the IMS stack.

    This bypasses the Android RIL path and sends directly through
    the SMS-over-IMS SIP MESSAGE flow (useful for testing).
    """
    try:
        from ims.sms import SMSoverIMS, SMSConfig
        from ims.sms_pdu import SMSSubmit, SMSAddress, DataCodingScheme

        # Build a TPDU and wrap in RIL format
        submit = SMSSubmit.create(
            dest_number=req.to,
            text=req.text,
            msg_ref=0,
        )
        tpdu = submit.to_bytes()
        pdu_hex = (bytes([0]) + tpdu).hex()

        # Try to get the running SMS service
        from ims.sms import _sms_state
        if not _sms_state.get("enabled"):
            raise HTTPException(status_code=503, detail="SMS service not running")

        # For direct API sending, we use a module-level reference
        from ims import _sms_service_ref
        if _sms_service_ref.instance:
            result = await _sms_service_ref.instance.send_sms("", pdu_hex)
            if result.get("errorCode", 1) == 0:
                return {"success": True, "messageRef": result.get("messageRef", 0)}
            raise HTTPException(status_code=502, detail="SMS delivery failed")

        raise HTTPException(status_code=503, detail="SMS service instance not available")

    except ImportError:
        raise HTTPException(status_code=503, detail="SMS module not available")


@app.get("/status/radio")
async def get_radio_status():
    """Get virtual radio / modem status (RIL bridge state)."""
    try:
        from hal.radio_hal import RadioHAL
        # Return default state; in production the HAL singleton would be used
        hal = RadioHAL()
        return hal.get_radio_state()
    except ImportError:
        return {
            "radioState": "UNAVAILABLE",
            "simPresent": False,
            "registration": {"state": "UNKNOWN", "rat": "UNKNOWN"},
        }
