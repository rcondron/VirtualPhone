"""
VoWiFi (Voice over Wi-Fi) implementation.

VoWiFi enables voice calls over Wi-Fi networks by establishing an IPsec
tunnel from the UE to the ePDG (Evolved Packet Data Gateway), then
running IMS/SIP over that tunnel.

Architecture:
  UE ──[IPsec/IKEv2]──> ePDG ──[GTP]──> PGW ──> IMS Core

The IPsec tunnel uses:
- IKEv2 for key exchange and tunnel management (RFC 7296)
- EAP-AKA' for authentication (RFC 5448)
- ESP for data encryption (RFC 4303)

This module manages the strongSwan IPsec daemon for tunnel establishment.

Reference: 3GPP TS 33.402, 3GPP TS 24.302
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class VoWiFiState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    FAILED = "failed"


@dataclass
class VoWiFiConfig:
    """VoWiFi tunnel configuration."""
    epdg_address: str = ""           # ePDG FQDN or IP
    apn: str = "ims"                 # IMS APN
    mcc: str = "001"
    mnc: str = "01"
    imsi: str = ""
    # EAP-AKA' credentials (passed to strongSwan)
    identity: str = ""               # NAI: 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    # Tunnel parameters
    local_ts: str = "0.0.0.0/0"     # Traffic selector (local)
    remote_ts: str = "0.0.0.0/0"    # Traffic selector (remote)
    # IPsec parameters
    ike_proposals: str = "aes256-sha256-modp2048"
    esp_proposals: str = "aes256-sha256"
    rekey_time: int = 3600


class VoWiFiTunnel:
    """
    VoWiFi IPsec tunnel manager.

    Uses strongSwan (charon) to establish an IKEv2/IPsec tunnel to the ePDG
    with EAP-AKA' authentication.
    """

    IPSEC_CONF_DIR = "/etc/swanctl/conf.d"
    VPHONE_CONN_NAME = "vowifi"

    def __init__(self, config: VoWiFiConfig):
        self.config = config
        self.state = VoWiFiState.DISCONNECTED
        self._tunnel_ip: Optional[str] = None
        self._dns_servers: list[str] = []
        self._pcscf_addresses: list[str] = []

    async def connect(self) -> bool:
        """
        Establish the VoWiFi IPsec tunnel.

        Steps:
        1. Generate strongSwan connection configuration
        2. Load the configuration into strongSwan
        3. Initiate the IKEv2 connection
        4. Wait for EAP-AKA' authentication to complete
        5. Extract assigned IP address and P-CSCF addresses
        """
        if not self.config.epdg_address:
            logger.error("No ePDG address configured")
            self.state = VoWiFiState.FAILED
            return False

        self.state = VoWiFiState.CONNECTING
        logger.info("Establishing VoWiFi tunnel to %s", self.config.epdg_address)

        try:
            # Generate NAI (Network Access Identifier) for EAP-AKA'
            nai = self._build_nai()

            # Write strongSwan configuration
            self._write_swanctl_config(nai)

            # Load and initiate connection
            await self._load_swanctl_config()

            self.state = VoWiFiState.AUTHENTICATING
            success = await self._initiate_connection()

            if success:
                self.state = VoWiFiState.CONNECTED
                # Extract tunnel information
                await self._extract_tunnel_info()
                logger.info(
                    "VoWiFi tunnel established. IP=%s, P-CSCF=%s",
                    self._tunnel_ip, self._pcscf_addresses,
                )
                return True
            else:
                self.state = VoWiFiState.FAILED
                logger.error("VoWiFi tunnel establishment failed")
                return False

        except Exception:
            self.state = VoWiFiState.FAILED
            logger.exception("VoWiFi connection error")
            return False

    async def disconnect(self) -> None:
        """Tear down the VoWiFi IPsec tunnel."""
        logger.info("Disconnecting VoWiFi tunnel...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "swanctl", "--terminate", "--ike", self.VPHONE_CONN_NAME,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        except Exception:
            logger.exception("Error disconnecting VoWiFi tunnel")
        finally:
            self.state = VoWiFiState.DISCONNECTED
            self._tunnel_ip = None
            self._pcscf_addresses = []

    def get_tunnel_info(self) -> dict:
        """Return current tunnel information."""
        return {
            "state": self.state.value,
            "epdg": self.config.epdg_address,
            "tunnel_ip": self._tunnel_ip,
            "pcscf_addresses": self._pcscf_addresses,
            "dns_servers": self._dns_servers,
        }

    def _build_nai(self) -> str:
        """
        Build the Network Access Identifier for EAP-AKA'.

        Format: 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
        """
        imsi = self.config.imsi or self.config.identity
        mnc = self.config.mnc.zfill(3)
        mcc = self.config.mcc.zfill(3)
        return f"0{imsi}@nai.epc.mnc{mnc}.mcc{mcc}.3gppnetwork.org"

    def _write_swanctl_config(self, nai: str) -> None:
        """Write the strongSwan swanctl connection configuration."""
        config = f"""
connections {{
    {self.VPHONE_CONN_NAME} {{
        # ePDG connection for VoWiFi
        remote_addrs = {self.config.epdg_address}
        version = 2

        # IKEv2 proposals
        proposals = {self.config.ike_proposals}
        rekey_time = {self.config.rekey_time}

        # EAP-AKA' authentication
        local {{
            auth = eap-aka
            eap_id = {nai}
            id = {nai}
        }}
        remote {{
            auth = pubkey
            id = %any
        }}

        children {{
            {self.VPHONE_CONN_NAME}-child {{
                # ESP proposals
                esp_proposals = {self.config.esp_proposals}
                local_ts = {self.config.local_ts}
                remote_ts = {self.config.remote_ts}

                # Request internal IP address (virtual IP)
                reqid = 1
            }}
        }}

        # Request configuration payloads
        # INTERNAL_IP4_ADDRESS, INTERNAL_IP4_DNS, P-CSCF
        send_cert = never
        vips = 0.0.0.0
    }}
}}

secrets {{
    eap-{self.VPHONE_CONN_NAME} {{
        id = {nai}
        secret = "virtual-eap-secret"
    }}
}}
"""
        conf_path = Path(self.IPSEC_CONF_DIR)
        conf_path.mkdir(parents=True, exist_ok=True)

        conf_file = conf_path / f"{self.VPHONE_CONN_NAME}.conf"
        conf_file.write_text(config)
        logger.debug("strongSwan config written to %s", conf_file)

    async def _load_swanctl_config(self) -> None:
        """Load configuration into strongSwan."""
        proc = await asyncio.create_subprocess_exec(
            "swanctl", "--load-all",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            logger.error("swanctl --load-all failed: %s", stderr.decode())
            raise RuntimeError(f"Failed to load strongSwan config: {stderr.decode()}")

        logger.debug("strongSwan config loaded: %s", stdout.decode().strip())

    async def _initiate_connection(self) -> bool:
        """Initiate the IKEv2 connection."""
        proc = await asyncio.create_subprocess_exec(
            "swanctl", "--initiate", "--child", f"{self.VPHONE_CONN_NAME}-child",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            logger.info("IKEv2 connection initiated: %s", stdout.decode().strip())
            return True

        logger.error("IKEv2 initiation failed: %s", stderr.decode())
        return False

    async def _extract_tunnel_info(self) -> None:
        """Extract assigned IP address and P-CSCF from the tunnel."""
        proc = await asyncio.create_subprocess_exec(
            "swanctl", "--list-sas", "--raw",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        output = stdout.decode()
        # Parse the output for virtual IP and other parameters
        for line in output.split("\n"):
            line = line.strip()
            if "local-vips" in line or "virtual-ip" in line:
                # Extract IP address
                parts = line.split()
                for part in parts:
                    if self._is_ip(part):
                        self._tunnel_ip = part
                        break

        # Also check ip addr for the virtual interface
        proc = await asyncio.create_subprocess_exec(
            "ip", "addr", "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        # Parse for tunnel interface IP

    @staticmethod
    def _is_ip(s: str) -> bool:
        """Check if a string looks like an IPv4 address."""
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @property
    def pcscf_address(self) -> Optional[str]:
        """Return the first P-CSCF address (for IMS registration)."""
        return self._pcscf_addresses[0] if self._pcscf_addresses else None

    @property
    def tunnel_ip(self) -> Optional[str]:
        return self._tunnel_ip
