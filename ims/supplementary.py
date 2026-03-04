"""
VoLTE supplementary services.

Implements call supplementary services per 3GPP TS 24.173 / TS 24.607:
- Call Hold / Resume via SIP re-INVITE with SDP direction change
- Call Waiting (second incoming call while active)
- Call Transfer via SIP REFER (attended and unattended)
- Conference Calls (multi-party merge)
- Call Forwarding (CFU, CFB, CFNR, CFNRc) rules
- USSD (Unstructured Supplementary Service Data)

Hold/Resume mechanism (3GPP TS 24.173 Section 4.5.3):
  Hold:   re-INVITE with SDP a=sendonly  → media paused
  Resume: re-INVITE with SDP a=sendrecv → media resumed

Transfer mechanism (RFC 3515):
  Unattended: SIP REFER to new target (blind transfer)
  Attended:   Hold A, dial B, merge, REFER A to B

Conference mechanism:
  Local merge: Hold call A, answer/dial call B, merge (is_mpty=True)
  Network:     re-INVITE to conference focus URI

Reference: 3GPP TS 24.173, 3GPP TS 24.607, RFC 3515 (REFER)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# =============================================================================
# Call Forwarding
# =============================================================================

class CallForwardReason(Enum):
    """Call forwarding condition types (3GPP TS 24.082)."""
    UNCONDITIONAL = 0      # CFU — always forward
    BUSY = 1               # CFB — forward when busy
    NO_REPLY = 2           # CFNR — forward when no answer
    NOT_REACHABLE = 3      # CFNRc — forward when not reachable
    ALL = 4                # All forwarding types
    ALL_CONDITIONAL = 5    # All conditional (busy + no-reply + not-reachable)


class CallForwardAction(Enum):
    """Call forwarding action (set/query/erase)."""
    DISABLE = 0
    ENABLE = 1
    QUERY = 2
    REGISTER = 3
    ERASE = 4


@dataclass
class CallForwardRule:
    """A single call forwarding rule."""
    reason: CallForwardReason = CallForwardReason.UNCONDITIONAL
    enabled: bool = False
    number: str = ""
    time_seconds: int = 20    # No-reply timeout (CFNR only)
    service_class: int = 1    # 1 = voice

    def to_dict(self) -> dict:
        return {
            "status": 1 if self.enabled else 0,
            "reason": self.reason.value,
            "serviceClass": self.service_class,
            "number": self.number,
            "timeSeconds": self.time_seconds,
        }


class CallForwardingManager:
    """
    Manages call forwarding rules.

    Stores and evaluates forwarding rules for incoming calls.
    In a real IMS network, these would be stored via XCAP
    (OMA-TS-XDM) or SIP SUBSCRIBE/NOTIFY.
    """

    def __init__(self):
        self._rules: dict[CallForwardReason, CallForwardRule] = {}

    def set_rule(self, reason: CallForwardReason, number: str,
                 time_seconds: int = 20) -> None:
        """Set (register + enable) a call forwarding rule."""
        self._rules[reason] = CallForwardRule(
            reason=reason,
            enabled=True,
            number=number,
            time_seconds=time_seconds,
        )
        logger.info("CF: set %s → %s (timeout=%ds)",
                     reason.name, number, time_seconds)

    def enable_rule(self, reason: CallForwardReason) -> bool:
        """Enable an existing forwarding rule."""
        rule = self._rules.get(reason)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, reason: CallForwardReason) -> bool:
        """Disable a forwarding rule (keeps the number)."""
        rule = self._rules.get(reason)
        if rule:
            rule.enabled = False
            return True
        return False

    def erase_rule(self, reason: CallForwardReason) -> bool:
        """Remove a forwarding rule entirely."""
        if reason == CallForwardReason.ALL:
            self._rules.clear()
            return True
        if reason == CallForwardReason.ALL_CONDITIONAL:
            for r in (CallForwardReason.BUSY, CallForwardReason.NO_REPLY,
                      CallForwardReason.NOT_REACHABLE):
                self._rules.pop(r, None)
            return True
        return self._rules.pop(reason, None) is not None

    def query_rule(self, reason: CallForwardReason) -> list[dict]:
        """Query forwarding rules for a given reason."""
        if reason == CallForwardReason.ALL:
            return [r.to_dict() for r in self._rules.values()]
        if reason == CallForwardReason.ALL_CONDITIONAL:
            return [
                r.to_dict() for r in self._rules.values()
                if r.reason in (CallForwardReason.BUSY,
                                CallForwardReason.NO_REPLY,
                                CallForwardReason.NOT_REACHABLE)
            ]
        rule = self._rules.get(reason)
        return [rule.to_dict()] if rule else []

    def should_forward(self, reason: CallForwardReason) -> Optional[str]:
        """
        Check if a call should be forwarded for the given reason.

        Returns the forwarding number if active, None otherwise.
        Also checks CFU (unconditional) which overrides all.
        """
        # Unconditional always wins
        cfu = self._rules.get(CallForwardReason.UNCONDITIONAL)
        if cfu and cfu.enabled:
            return cfu.number

        rule = self._rules.get(reason)
        if rule and rule.enabled:
            return rule.number

        return None

    def get_all_rules(self) -> list[dict]:
        """Return all forwarding rules for management API."""
        return [r.to_dict() for r in self._rules.values()]


# =============================================================================
# USSD
# =============================================================================

class USSDState(Enum):
    """USSD session state."""
    IDLE = "idle"
    ACTIVE = "active"
    PENDING = "pending"


@dataclass
class USSDSession:
    """An active USSD session."""
    code: str = ""
    state: USSDState = USSDState.IDLE
    response: str = ""
    response_type: int = 0  # 0=no further action, 1=action needed, 2=terminated


class USSDHandler:
    """
    USSD (Unstructured Supplementary Service Data) handler.

    Handles MMI codes like *#06# (show IMEI), *21*number# (set CFU),
    *#21# (query CFU), etc.

    In a real network, USSD is carried over SIP or MAP signaling.
    Here we handle common codes locally and return simulated responses.
    """

    def __init__(self, call_forwarding: Optional[CallForwardingManager] = None):
        self._session: Optional[USSDSession] = None
        self._cf = call_forwarding or CallForwardingManager()
        self._imei: str = "358240051111110"

    def set_imei(self, imei: str) -> None:
        self._imei = imei

    def send_ussd(self, code: str) -> dict:
        """
        Process a USSD code and return the response.

        Returns a dict with:
          - type: 0=notify, 1=request, 2=session terminated
          - message: Human-readable response
        """
        code = code.strip()
        logger.info("USSD: processing code '%s'", code)

        # *#06# — Show IMEI
        if code in ("*#06#", "*#06*#"):
            return self._respond(0, f"IMEI: {self._imei}")

        # Call forwarding codes
        # *21*<number># — Set CFU (unconditional)
        # **21*<number># — Register CFU
        # #21# — Deactivate CFU
        # *#21# — Query CFU
        # *61*<number># — Set CFNR
        # *62*<number># — Set CFNRc
        # *67*<number># — Set CFB
        cf_result = self._handle_cf_code(code)
        if cf_result is not None:
            return cf_result

        # *#*#4636#*#* — Phone info (Android)
        if code == "*#*#4636#*#*":
            return self._respond(0, "Virtual Phone Info\nNetwork: LTE\nSIM: Active")

        # Balance inquiry (common prefix)
        if code.startswith("*") and code.endswith("#") and len(code) <= 6:
            return self._respond(0, "Balance: $50.00\nValid until: 2025-12-31")

        # Unknown code
        return self._respond(2, "USSD code not recognized")

    def cancel_ussd(self) -> dict:
        """Cancel the current USSD session."""
        self._session = None
        return {"success": True}

    def _handle_cf_code(self, code: str) -> Optional[dict]:
        """Handle call forwarding MMI codes."""
        import re

        # Map service code to reason
        cf_codes = {
            "21": CallForwardReason.UNCONDITIONAL,
            "61": CallForwardReason.NO_REPLY,
            "62": CallForwardReason.NOT_REACHABLE,
            "67": CallForwardReason.BUSY,
        }

        # Query: *#<code>#
        m = re.match(r'^\*#(\d{2})#$', code)
        if m and m.group(1) in cf_codes:
            reason = cf_codes[m.group(1)]
            rules = self._cf.query_rule(reason)
            if rules and rules[0].get("status"):
                return self._respond(
                    0, f"Call Forwarding {reason.name}: Active\n"
                       f"Number: {rules[0]['number']}")
            return self._respond(0, f"Call Forwarding {reason.name}: Not active")

        # Set/Register: *<code>*<number># or **<code>*<number>#
        m = re.match(r'^\*\*?(\d{2})\*([+\d]+)#$', code)
        if m and m.group(1) in cf_codes:
            reason = cf_codes[m.group(1)]
            number = m.group(2)
            self._cf.set_rule(reason, number)
            return self._respond(
                0, f"Call Forwarding {reason.name}: Registered\n"
                   f"Number: {number}")

        # Deactivate: #<code>#
        m = re.match(r'^#(\d{2})#$', code)
        if m and m.group(1) in cf_codes:
            reason = cf_codes[m.group(1)]
            self._cf.disable_rule(reason)
            return self._respond(0, f"Call Forwarding {reason.name}: Deactivated")

        # Erase: ##<code>#
        m = re.match(r'^##(\d{2})#$', code)
        if m and m.group(1) in cf_codes:
            reason = cf_codes[m.group(1)]
            self._cf.erase_rule(reason)
            return self._respond(0, f"Call Forwarding {reason.name}: Erased")

        return None

    def _respond(self, msg_type: int, message: str) -> dict:
        """Build a USSD response."""
        self._session = USSDSession(
            state=USSDState.IDLE if msg_type != 1 else USSDState.ACTIVE,
            response=message,
            response_type=msg_type,
        )
        return {
            "type": msg_type,
            "message": message,
        }


# =============================================================================
# Supplementary Service State (module-level)
# =============================================================================

_supplementary_state: dict = {
    "call_forwarding_rules": [],
    "ussd_session_active": False,
    "held_calls": 0,
    "conference_calls": 0,
}


def get_supplementary_state() -> dict:
    """Return supplementary service state for the management API."""
    return dict(_supplementary_state)


def update_supplementary_state(
    cf_manager: Optional[CallForwardingManager] = None,
    held: int = 0,
    conference: int = 0,
) -> None:
    """Update the module-level supplementary service state."""
    global _supplementary_state
    if cf_manager:
        _supplementary_state["call_forwarding_rules"] = cf_manager.get_all_rules()
    _supplementary_state["held_calls"] = held
    _supplementary_state["conference_calls"] = conference
