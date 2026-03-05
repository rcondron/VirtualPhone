# VirtualPhone — Production Roadmap

## PHASE 1: Core eUICC & Management API (Week 1-2)
**Goal:** Working virtual eUICC with REST API, testable in Docker

1. Fix Python packaging — add `__main__.py` entry points, `pyproject.toml`
2. Write unit tests for Milenage (verify against 3GPP test vectors TS 35.207)
3. Write unit tests for SCP03 key derivation
4. Write integration tests for eUICC daemon — install/enable/disable/delete profiles via Unix socket
5. Get `docker-compose up` working for just the `vphone` container (no redroid yet)
6. Validate management API — all CRUD endpoints for profiles via `curl`
7. Add API authentication (API key or mTLS) to the management API
8. Add persistent logging with structured JSON output
9. Add Prometheus metrics endpoint (`/metrics`) — profile count, API latency, errors

**Deliverable:** `docker-compose up vphone` → REST API on :9000, install test profile, verify via API

---

## PHASE 2: Test IMS Core (Week 2-3)
**Goal:** Local IMS network to register and authenticate against

1. Add Open5GS containers to docker-compose (MME, HSS, PCRF, PGW, SGW)
2. Add Kamailio IMS containers (P-CSCF, I-CSCF, S-CSCF)
3. Configure HSS with test subscriber matching `euicc_config.yaml` test profile (IMSI/Ki/OPc)
4. Configure Kamailio IMS domain to match `ims.mnc001.mcc001.3gppnetwork.org`
5. Verify DNS resolution within the docker network — `_sip._udp.ims.domain` SRV records
6. Test raw SIP REGISTER from a SIP client (e.g., pjsip) against the local IMS core
7. Wire IMS service to register against the local P-CSCF
8. Debug AKA challenge-response — verify RAND/AUTN/RES flow between eUICC ↔ IMS ↔ HSS
9. Achieve successful IMS registration (200 OK)
10. Add IMS status to management API (`/status/ims` returning real state)

**Deliverable:** Virtual eUICC authenticates and registers with local IMS core over SIP

---

## PHASE 3: VoWiFi Tunnel (Week 3-4)
**Goal:** IPsec tunnel from vphone to local ePDG, IMS over tunnel

1. Add ePDG container (strongSwan-based) to docker-compose
2. Write custom strongSwan EAP-AKA plugin that calls eUICC daemon for auth vectors
3. Configure ePDG with correct 3GPP vendor attributes (P-CSCF delivery via IKEv2 CFG_REPLY)
4. Build NAI correctly: `0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`
5. Establish IKEv2 tunnel from vphone → ePDG with EAP-AKA auth
6. Verify virtual IP assignment and P-CSCF address delivery via tunnel
7. Route IMS SIP traffic through the IPsec tunnel
8. Re-verify IMS registration over VoWiFi path
9. Add keepalive/DPD handling for tunnel stability
10. Add VoWiFi status to management API with tunnel metrics

**Deliverable:** Full VoWiFi path — IPsec tunnel → P-CSCF discovery → IMS registration

---

## PHASE 4: RIL Bridge (Week 4-7)
**Goal:** Android telephony framework in redroid talks to virtual modem

### 4a. Understand redroid's telephony stack
1. Boot redroid standalone, connect via ADB (`adb connect localhost:5555`)
2. Inspect `/dev/socket/rild` — determine if redroid includes a RIL daemon
3. Check `getprop gsm.version.ril-impl` and `dumpsys telephony.registry`
4. Identify which RIL implementation redroid ships (if any)

### 4b. Build a native RIL shim
5. Write a C/C++ `rild` replacement using Android's Parcel-based RIL protocol (AOSP `hardware/ril/libril/`)
6. The shim opens a TCP connection to vphone container's RIL bridge (port 18000)
7. Translate Parcel ↔ JSON between Android and Python RIL bridge
8. Key RIL solicited commands:
   - `RIL_REQUEST_GET_SIM_STATUS` (1)
   - `RIL_REQUEST_GET_IMSI` (11)
   - `RIL_REQUEST_OPERATOR` (22)
   - `RIL_REQUEST_RADIO_POWER` (23)
   - `RIL_REQUEST_REGISTRATION_STATE` (20/21)
   - `RIL_REQUEST_SIGNAL_STRENGTH` (19)
   - `RIL_REQUEST_SEND_SMS` (25)
   - `RIL_REQUEST_SIM_IO` (28)
   - `RIL_REQUEST_SIM_AUTHENTICATION` (125)
9. Key unsolicited indications:
   - `RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED` (1000)
   - `RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED` (1001)
   - `RIL_UNSOL_RESPONSE_NEW_SMS` (1003)
   - `RIL_UNSOL_SIM_STATUS_CHANGED` (1019)

### 4c. Inject into redroid
10. Build custom redroid image with RIL shim replacing default `rild`
11. Mount shim binary via docker volume: `./ril_shim:/vendor/bin/hw/rild`
12. Set system properties via redroid command line:
    - `ro.telephony.default_network=13` (LTE)
    - `gsm.nitz.time` (network time)
    - `gsm.sim.state=READY`
    - `gsm.operator.numeric=00101`
13. Verify via ADB: `adb shell service call phone 1` → SIM status returned
14. Verify Android Settings → SIM shows virtual operator name and phone number

### 4d. eUICC HAL integration
15. Implement IEuicc HIDL/AIDL service (or use EuiccManager ADB path)
16. Wire `Settings → Network → SIM → Add eSIM` to call eUICC HAL
17. Verify profile download flow from Android UI → LPA → ES9+ → eUICC daemon

**Deliverable:** `adb shell` shows SIM present, operator name, signal bars. Android dialer shows phone number.

---

## PHASE 5: SMS over IMS (Week 7-8)
**Goal:** Send and receive SMS via SIP MESSAGE

1. Implement SIP MESSAGE method in SIP client (RFC 3428)
2. Handle SMS-over-IP encoding (3GPP TS 24.341)
3. Wire RIL_REQUEST_SEND_SMS → IMS service → SIP MESSAGE → P-CSCF
4. Handle incoming SIP MESSAGE → RIL_UNSOL_RESPONSE_NEW_SMS → Android SMS app
5. Implement SMS delivery reports
6. Test end-to-end: Android Messages app → send SMS → arrives at IMS core
7. Add SMS gateway for bridging to PSTN (via Twilio/Telnyx API as interim)

**Deliverable:** Send/receive SMS from Android Messages app in redroid

---

## PHASE 6: Voice Calls — VoWiFi (Week 8-10)
**Goal:** Make and receive voice calls over WiFi

1. Implement SIP INVITE flow (RFC 3261)
2. Build SDP offer/answer negotiation
3. Implement RTP media handling (`aiortc` or `gstreamer`)
4. Handle codec negotiation: AMR-WB preferred, AMR-NB fallback
5. Wire RIL_REQUEST_DIAL → IMS service → SIP INVITE → P-CSCF
6. Handle incoming INVITE → RIL indication → Android dialer rings
7. Implement DTMF (RFC 4733)
8. Implement call hold/resume (SIP re-INVITE)
9. Implement call transfer (SIP REFER)
10. Test: Android dialer → dial number → audio flows → hang up

**Deliverable:** Two-way voice calls from Android dialer over VoWiFi

---

## PHASE 7: RSP Profile Download from Real SM-DP+ (Week 10-11)
**Goal:** Download real eSIM profiles from carrier SM-DP+ servers

1. Implement full GSMA CI certificate chain validation
2. Generate proper eUICC certificates signed by a test CI
3. Implement full SCP03 secure channel for profile decryption
4. Test against sysmocom SM-DP+ or build test SM-DP+
5. Test with real consumer eSIM (e.g., Airalo travel eSIM)
6. Handle profile policy rules (PPR)

**Deliverable:** Scan QR code in Android → profile downloads and installs → operator appears

---

## PHASE 8: Production Hardening (Week 11-13)
**Goal:** Production-ready Docker deployment

### Security
- Encrypt profile storage at rest
- mTLS on internal sockets
- API rate limiting and auth
- Docker secrets or Vault for key material
- Security audit of RIL bridge

### Reliability
- Supervisor watchdog for all services
- Graceful degradation on service restart
- Health checks with dependency ordering
- Profile backup/restore

### Observability
- Structured logging
- Prometheus metrics
- Grafana dashboard template
- Alerting rules

### Scalability
- One docker-compose stack = one virtual phone
- Kubernetes Helm chart
- Shared IMS core for multi-phone deployments
- Fleet management API

### Documentation
- README with quick-start
- Architecture diagram
- OpenAPI/Swagger docs
- Troubleshooting guide

**Deliverable:** `docker-compose up` → fully functional virtual phone

---

## PHASE 9: Carrier Interop (Week 13+)
**Goal:** Work with actual carrier networks

1. sysmoISIM-SJA5 cards for hardware-backed testing
2. Test against real carrier ePDGs (T-Mobile, AT&T)
3. Debug carrier-specific IMS quirks
4. Implement carrier-specific APNs and IMS configs
5. Test multi-carrier profile switching

---

## Timeline Summary

| Phase | Weeks | Description |
|-------|-------|-------------|
| 1 | 1-2 | Foundation (eUICC + API) |
| 2 | 2-3 | Test IMS core |
| 3 | 3-4 | VoWiFi tunnel |
| 4 | 4-7 | RIL bridge (critical path) |
| 5 | 7-8 | SMS over IMS |
| 6 | 8-10 | Voice calls |
| 7 | 10-11 | Real eSIM profiles |
| 8 | 11-13 | Production hardening |
| 9 | 13+ | Carrier interop |

**Critical Path:** Phase 4 (RIL bridge) is the gating item. Phases 2-3 can run in parallel.
