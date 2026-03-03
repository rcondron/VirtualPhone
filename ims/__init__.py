"""
IMS (IP Multimedia Subsystem) and VoWiFi stack.

Implements:
- SIP client for IMS registration and session management
- IMS registration with authentication (SIP REGISTER + EAP-AKA)
- SMS over IMS via SIP MESSAGE (3GPP TS 24.341)
- VoWiFi support via IPsec/IKEv2 with EAP-AKA'
- VoLTE support via SIP over IPsec
"""

from typing import Optional


class _SMSServiceRef:
    """Module-level reference to the running SMS service (for management API)."""
    instance: Optional["ims.sms.SMSoverIMS"] = None


class _VoLTEManagerRef:
    """Module-level reference to the running VoLTE call manager (for management API)."""
    instance: Optional["ims.volte.VoLTECallManager"] = None


_sms_service_ref = _SMSServiceRef()
_volte_manager_ref = _VoLTEManagerRef()
