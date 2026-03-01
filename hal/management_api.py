"""
Management REST API for the VirtualPhone environment.

Provides HTTP endpoints for:
- eUICC status and profile management
- Profile installation (direct and via RSP)
- IMS registration status
- VoWiFi tunnel status
- Health monitoring

Runs on port 9000 via uvicorn.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI(
    title="VirtualPhone Management API",
    description="Manage the virtual eUICC, eSIM profiles, and telecom services",
    version="1.0.0",
)

EUICC_SOCKET = "/run/vphone/euicc.sock"
RSP_SOCKET = "/run/vphone/rsp.sock"


# -- Request/Response models ----------------------------------------------

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


# -- Socket communication helpers -----------------------------------------

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


# -- Health ---------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        resp = await _send_euicc({"type": "get_info"})
        euicc_ok = "data" in resp
    except Exception:
        euicc_ok = False

    return {
        "status": "healthy" if euicc_ok else "degraded",
        "euicc": "ok" if euicc_ok else "unavailable",
    }


# -- eUICC Information ----------------------------------------------------

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


# -- Profile Management --------------------------------------------------

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
        return {"success": True, "message": f"Profile {iccid} deleted"}
    raise HTTPException(status_code=400, detail="Failed to delete profile")


# -- Telecom Status -------------------------------------------------------

@app.get("/status/ims")
async def get_ims_status():
    """Get IMS registration status."""
    return {
        "note": "IMS status polling not yet connected",
        "domain": os.environ.get("VPHONE_IMS_DOMAIN", ""),
    }


@app.get("/status/vowifi")
async def get_vowifi_status():
    """Get VoWiFi tunnel status."""
    return {
        "note": "VoWiFi status polling not yet connected",
        "epdg": os.environ.get("VPHONE_VOWIFI_EPDG", ""),
    }
