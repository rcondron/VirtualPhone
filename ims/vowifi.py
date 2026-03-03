"""
VoWiFi (Voice over Wi-Fi) implementation.

VoWiFi enables voice calls over Wi-Fi networks by establishing an IPsec
tunnel from the UE to the ePDG (Evolved Packet Data Gateway), then
running IMS/SIP over that tunnel.

Architecture:
  UE ──[IPsec/IKEv2]──> ePDG ──[GTP]──> PGW ──> IMS Core

The IPsec tunnel uses:
- IKEv2 for key exchange and tunnel management (RFC 7296)
- EAP-AKA for authentication using Milenage (RFC 4187)
- ESP for data encryption (RFC 4303)

On both sides (UE and ePDG), strongSwan's eap-simaka-sql plugin provides
pre-generated AKA quintuplets from the subscriber's Ki/OPc via Milenage.

This module manages the strongSwan IPsec daemon for tunnel establishment.

Reference: 3GPP TS 33.402, 3GPP TS 24.302
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sqlite3
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
    ki: bytes = b""                  # Subscriber Ki (for quintuplet generation)
    opc: bytes = b""                 # Subscriber OPc (for quintuplet generation)
    sqn: int = 32                    # AKA sequence number
    # Tunnel parameters
    local_ts: str = "0.0.0.0/0"     # Traffic selector (local)
    remote_ts: str = "0.0.0.0/0"    # Traffic selector (remote)
    # IPsec parameters
    ike_proposals: str = "aes256-sha256-modp2048"
    esp_proposals: str = "aes256-sha256"
    rekey_time: int = 3600
    # DPD (Dead Peer Detection)
    dpd_delay: int = 30              # seconds
    dpd_timeout: int = 150           # seconds
    # ePDG CA certificate path (for verifying ePDG identity)
    epdg_ca_cert: str = "/var/lib/epdg/ca.cert.pem"
    # Quintuplet database path
    quintuplet_db: str = "/var/lib/epdg/aka_quintuplets.db"
    # Number of quintuplets to pre-generate
    quintuplet_count: int = 50


# Module-level VoWiFi state for the management API
_vowifi_state: dict = {
    "state": VoWiFiState.DISCONNECTED.value,
    "tunnel_up": False,
    "epdg": "",
    "tunnel_ip": None,
    "pcscf_addresses": [],
    "dns_servers": [],
    "dpd_ok": True,
}


def get_vowifi_state() -> dict:
    """Return the current VoWiFi tunnel state (called by management API)."""
    return dict(_vowifi_state)


class VoWiFiTunnel:
    """
    VoWiFi IPsec tunnel manager.

    Uses strongSwan (charon) to establish an IKEv2/IPsec tunnel to the ePDG
    with EAP-AKA authentication backed by simaka-sql quintuplets.
    """

    SWANCTL_CONF_DIR = "/etc/swanctl/conf.d"
    VPHONE_CONN_NAME = "vowifi"

    def __init__(self, config: VoWiFiConfig):
        self.config = config
        self.state = VoWiFiState.DISCONNECTED
        self._tunnel_ip: Optional[str] = None
        self._dns_servers: list[str] = []
        self._pcscf_addresses: list[str] = []
        self._dpd_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        """
        Establish the VoWiFi IPsec tunnel.

        Steps:
        1. Generate client-side AKA quintuplets (simaka-sql DB)
        2. Write strongSwan swanctl connection configuration
        3. Configure strongswan.conf for simaka-sql
        4. Load the configuration into strongSwan
        5. Initiate the IKEv2 connection (EAP-AKA handshake)
        6. Extract assigned virtual IP and P-CSCF addresses
        7. Start DPD monitoring
        """
        global _vowifi_state

        if not self.config.epdg_address:
            logger.error("No ePDG address configured")
            self.state = VoWiFiState.FAILED
            _vowifi_state.update({"state": self.state.value, "tunnel_up": False})
            return False

        self.state = VoWiFiState.CONNECTING
        _vowifi_state.update({
            "state": self.state.value,
            "epdg": self.config.epdg_address,
        })
        logger.info("Establishing VoWiFi tunnel to %s", self.config.epdg_address)

        try:
            # Step 1: Verify client-side quintuplets for EAP-AKA
            if self.config.ki and self.config.opc:
                self._verify_client_quintuplets()

            # Step 2: Write strongSwan client config
            nai = self._build_nai()
            self._write_swanctl_config(nai)
            self._write_strongswan_conf()

            # Step 3: Load configuration
            await self._load_swanctl_config()

            # Step 4: Initiate connection (EAP-AKA exchange)
            self.state = VoWiFiState.AUTHENTICATING
            _vowifi_state["state"] = self.state.value
            success = await self._initiate_connection()

            if success:
                self.state = VoWiFiState.CONNECTED
                # Step 5: Extract tunnel info
                await self._extract_tunnel_info()
                _vowifi_state.update({
                    "state": self.state.value,
                    "tunnel_up": True,
                    "tunnel_ip": self._tunnel_ip,
                    "pcscf_addresses": self._pcscf_addresses,
                    "dns_servers": self._dns_servers,
                })
                logger.info(
                    "VoWiFi tunnel established. IP=%s, P-CSCF=%s, DNS=%s",
                    self._tunnel_ip, self._pcscf_addresses, self._dns_servers,
                )

                # Step 6: Start DPD monitoring
                self._dpd_task = asyncio.ensure_future(self._dpd_monitor())

                return True
            else:
                self.state = VoWiFiState.FAILED
                _vowifi_state.update({"state": self.state.value, "tunnel_up": False})
                logger.error("VoWiFi tunnel establishment failed")
                return False

        except Exception:
            self.state = VoWiFiState.FAILED
            _vowifi_state.update({"state": self.state.value, "tunnel_up": False})
            logger.exception("VoWiFi connection error")
            return False

    async def disconnect(self) -> None:
        """Tear down the VoWiFi IPsec tunnel."""
        global _vowifi_state
        logger.info("Disconnecting VoWiFi tunnel...")

        # Cancel DPD monitor
        if self._dpd_task:
            self._dpd_task.cancel()
            self._dpd_task = None

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
            self._dns_servers = []
            _vowifi_state.update({
                "state": self.state.value,
                "tunnel_up": False,
                "tunnel_ip": None,
                "pcscf_addresses": [],
                "dns_servers": [],
            })

    def get_tunnel_info(self) -> dict:
        """Return current tunnel information."""
        return {
            "state": self.state.value,
            "epdg": self.config.epdg_address,
            "tunnel_ip": self._tunnel_ip,
            "pcscf_addresses": self._pcscf_addresses,
            "dns_servers": self._dns_servers,
        }

    # ---- NAI Construction -------------------------------------------------------

    @staticmethod
    def build_nai(imsi: str, mcc: str, mnc: str) -> str:
        """
        Build the Network Access Identifier for EAP-AKA.

        Format: 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
        Per 3GPP TS 23.003 Section 19.3
        """
        return f"0{imsi}@nai.epc.mnc{mnc.zfill(3)}.mcc{mcc.zfill(3)}.3gppnetwork.org"

    def _build_nai(self) -> str:
        return self.build_nai(self.config.imsi, self.config.mcc, self.config.mnc)

    # ---- Client Quintuplet Verification -----------------------------------------

    def _verify_client_quintuplets(self) -> None:
        """Verify that the shared quintuplet DB has entries for this subscriber."""
        db_path = self.config.quintuplet_db
        if not os.path.exists(db_path):
            logger.warning("Quintuplet DB not found at %s", db_path)
            return

        nai = self._build_nai()
        try:
            conn = sqlite3.connect(db_path)
            count = conn.execute(
                "SELECT COUNT(*) FROM quintuplets WHERE permanent = ?", (nai,)
            ).fetchone()[0]
            conn.close()
            logger.info("Client quintuplet DB: %d entries for %s", count, nai)
        except Exception as e:
            logger.warning("Could not verify quintuplet DB: %s", e)

    # ---- strongSwan Configuration -----------------------------------------------

    def _write_swanctl_config(self, nai: str) -> None:
        """Write the strongSwan swanctl connection configuration for the UE."""
        epdg_ca = self.config.epdg_ca_cert
        if os.path.exists(epdg_ca):
            remote_block = (
                f"auth = pubkey\n"
                f"            cacerts = {os.path.basename(epdg_ca)}"
            )
        else:
            remote_block = "auth = pubkey\n            id = %any"

        config = f"""# VoWiFi client connection (auto-generated)
connections {{
    {self.VPHONE_CONN_NAME} {{
        # ePDG server
        remote_addrs = {self.config.epdg_address}
        version = 2

        # IKEv2 proposals
        proposals = {self.config.ike_proposals}
        rekey_time = {self.config.rekey_time}

        # Dead Peer Detection
        dpd_delay = {self.config.dpd_delay}s

        # UE authenticates with EAP-AKA
        local {{
            auth = eap-aka
            eap_id = {nai}
            id = {nai}
        }}

        # ePDG authenticates with certificate
        remote {{
            {remote_block}
        }}

        children {{
            {self.VPHONE_CONN_NAME}-child {{
                # ESP proposals
                esp_proposals = {self.config.esp_proposals}
                local_ts = {self.config.local_ts}
                remote_ts = {self.config.remote_ts}
                dpd_action = restart
                rekey_time = {self.config.rekey_time}s
            }}
        }}

        # Request virtual IP and configuration from ePDG
        vips = 0.0.0.0
        send_cert = never
    }}
}}
"""
        conf_path = Path(self.SWANCTL_CONF_DIR)
        conf_path.mkdir(parents=True, exist_ok=True)

        conf_file = conf_path / f"{self.VPHONE_CONN_NAME}.conf"
        conf_file.write_text(config)
        logger.debug("swanctl config written to %s", conf_file)

    def _write_strongswan_conf(self) -> None:
        """Write the client-side strongswan.conf for simaka-sql."""
        db_path = self.config.quintuplet_db

        config = f"""# VoWiFi client strongSwan config (auto-generated)
charon {{
    load_modular = yes
    plugins {{
        eap-aka {{
        }}
        eap-simaka-sql {{
            database = sqlite://{db_path}
        }}
    }}
}}
"""
        conf_dir = Path("/etc/strongswan.d")
        if conf_dir.exists():
            (conf_dir / "vowifi.conf").write_text(config)
        else:
            main_conf = Path("/etc/strongswan.conf")
            if main_conf.exists():
                existing = main_conf.read_text()
                if "eap-simaka-sql" not in existing:
                    main_conf.write_text(existing + "\n" + config)

        logger.debug("strongswan.conf updated for simaka-sql")

    # ---- strongSwan Control -----------------------------------------------------

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
        """Initiate the IKEv2 connection with EAP-AKA authentication."""
        proc = await asyncio.create_subprocess_exec(
            "swanctl", "--initiate", "--child", f"{self.VPHONE_CONN_NAME}-child",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            logger.info("IKEv2/EAP-AKA connection established: %s", stdout.decode().strip())
            return True

        logger.error("IKEv2/EAP-AKA initiation failed: %s", stderr.decode())
        return False

    # ---- Tunnel Info Extraction -------------------------------------------------

    async def _extract_tunnel_info(self) -> None:
        """
        Extract assigned virtual IP, DNS servers, and P-CSCF addresses
        from the established IKEv2 SA.
        """
        proc = await asyncio.create_subprocess_exec(
            "swanctl", "--list-sas", "--raw",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode()

        if not output.strip():
            logger.warning("No SAs found from swanctl --list-sas")
            return

        # Parse virtual IP (local-vips field)
        vip_match = re.search(r'local-vips\s*=\s*\{([^}]+)\}', output)
        if not vip_match:
            vip_match = re.search(r'virtual-ip\s*[=:]\s*([\d.]+)', output)
        if vip_match:
            vip_text = vip_match.group(1)
            for part in re.findall(r'(\d+\.\d+\.\d+\.\d+)', vip_text):
                self._tunnel_ip = part
                break

        # Parse DNS servers from CFG_REPLY
        dns_match = re.search(r'dns\s*=\s*\{([^}]+)\}', output)
        if dns_match:
            self._dns_servers = re.findall(r'(\d+\.\d+\.\d+\.\d+)', dns_match.group(1))

        # Try to extract P-CSCF from vendor attributes (3GPP attribute 16384)
        pcscf_match = re.search(r'16384-10415\s*=\s*\{([^}]+)\}', output)
        if pcscf_match:
            self._pcscf_addresses = re.findall(r'(\d+\.\d+\.\d+\.\d+)', pcscf_match.group(1))

        # If no P-CSCF from tunnel, fall back to env config
        if not self._pcscf_addresses:
            pcscf_env = os.environ.get("VPHONE_IMS_PROXY", "")
            if pcscf_env:
                self._pcscf_addresses = [pcscf_env]
                logger.info("Using P-CSCF from config: %s", pcscf_env)

        # Fallback: check ip addr for tunnel interface IP
        if not self._tunnel_ip:
            await self._extract_ip_from_interface()

    async def _extract_ip_from_interface(self) -> None:
        """Extract tunnel IP from network interfaces as fallback."""
        proc = await asyncio.create_subprocess_exec(
            "ip", "-4", "addr", "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()

        # Look for addresses in the 10.47.x.x range (our VoWiFi pool)
        for match in re.finditer(r'inet\s+(10\.47\.\d+\.\d+)', output):
            self._tunnel_ip = match.group(1)
            logger.info("Tunnel IP from interface: %s", self._tunnel_ip)
            break

    # ---- DPD (Dead Peer Detection) Monitoring -----------------------------------

    async def _dpd_monitor(self) -> None:
        """Monitor tunnel health via periodic SA status checks."""
        global _vowifi_state
        while True:
            try:
                await asyncio.sleep(self.config.dpd_delay)

                proc = await asyncio.create_subprocess_exec(
                    "swanctl", "--list-sas", "--ike", self.VPHONE_CONN_NAME,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode()

                if self.VPHONE_CONN_NAME in output and "ESTABLISHED" in output:
                    _vowifi_state["dpd_ok"] = True
                else:
                    logger.warning("DPD: Tunnel SA not found or not ESTABLISHED")
                    _vowifi_state["dpd_ok"] = False

                    if self.state == VoWiFiState.CONNECTED:
                        logger.info("DPD: Attempting tunnel reconnection...")
                        self.state = VoWiFiState.CONNECTING
                        _vowifi_state.update({
                            "state": self.state.value,
                            "tunnel_up": False,
                        })
                        success = await self._initiate_connection()
                        if success:
                            self.state = VoWiFiState.CONNECTED
                            await self._extract_tunnel_info()
                            _vowifi_state.update({
                                "state": self.state.value,
                                "tunnel_up": True,
                                "tunnel_ip": self._tunnel_ip,
                            })
                        else:
                            self.state = VoWiFiState.FAILED
                            _vowifi_state.update({
                                "state": self.state.value,
                                "tunnel_up": False,
                            })

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("DPD monitor error")

    # ---- Properties -------------------------------------------------------------

    @property
    def pcscf_address(self) -> Optional[str]:
        """Return the first P-CSCF address (for IMS registration)."""
        return self._pcscf_addresses[0] if self._pcscf_addresses else None

    @property
    def tunnel_ip(self) -> Optional[str]:
        return self._tunnel_ip
