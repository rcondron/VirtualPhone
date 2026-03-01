"""
Virtual eUICC (Embedded Universal Integrated Circuit Card) implementation.

Implements GSMA SGP.22 compliant eUICC with:
- ISD-R (Issuer Security Domain - Root) management
- ISD-P (Issuer Security Domain - Profile) lifecycle
- APDU command processing (ISO 7816-4)
- eSIM profile storage and activation
"""

__version__ = "1.0.0"
