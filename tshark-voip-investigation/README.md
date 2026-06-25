# SOC Investigation Report

**Report Title:** VoIP Traffic Analysis — Unauthorized SIP Communication & Credential Exposure  
**Analysis Type:** Network Traffic Analysis · Tshark · VoIP Investigation  
**Analyst:** Miro Lerch  
**Date:** 2026-06-25
**Severity:** Medium  
**Status:** Closed

---

## Executive Summary

A packet capture of internal VoIP traffic (`VoIP_traffic.pcap`) was analyzed to reconstruct SIP signaling activity, identify endpoint behavior, and assess potential exposure. The analysis revealed a single internal host (`192.168.10.15`) operating the Zoiper SIP client, registering repeatedly against an external SIP provider (`208.51.63.146`) using extension `085499826`. During the capture window, the client transmitted an unencrypted plaintext SIP MESSAGE and successfully completed at least one voice call to external number `+918108591527`. SIP authentication digest hashes (MD5) were exposed in cleartext across multiple REGISTER exchanges. No encryption (SRTP/TLS) was observed on either signaling or media streams.

---

## Threat Summary

| Field | Value |
|-------|-------|
| **Capture file** | `VoIP_traffic.pcap` |
| **Protocol** | SIP / RTP / SDP (UDP) |
| **Internal client IP** | 192.168.10.15 |
| **VoIP client** | Zoiper r656527b |
| **SIP server (external)** | 208.51.63.146 |
| **SIP domain** | sip.callwithus.com |
| **Calling extension** | 085499826 |
| **Called number** | +918108591527 (India, CC 91) |
| **Message content** | `Dude test text` (plaintext) |
| **Auth mechanism** | Digest / MD5 (cleartext in capture) |
| **Media encryption** | None observed |

---

## Analysis

### Phase 1 — Initial Traffic Overview

To establish baseline visibility, all SIP and RTP traffic was extracted from the capture:

```bash
tshark -r VoIP_traffic.pcap -Y "sip or rtp" | more
```

The output confirmed bidirectional SIP signaling between internal host `192.168.10.15` and external SIP server `208.51.63.146` (UDP/5060), along with RTP media streams on dynamic ports. SIP methods observed include `REGISTER`, `MESSAGE`, `INVITE`, `ACK`, and `BYE`.

---

### Phase 2 — Client Identification

To identify the VoIP software in use, the SIP User-Agent string was targeted via payload substring match:

```bash
tshark -r VoIP_traffic.pcap -Y "sip contains Zoiper" -Tfields -e ip.src
```

**Result:** All matching packets originated from `192.168.10.15`. The full SIP header disclosed `User-Agent: Zoiper r656527b`, identifying the client software and version unambiguously.

---

### Phase 3 — SIP Server Identification

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER" -Tfields -e ip.dst
```

**Result:** All REGISTER requests were directed to `208.51.63.146`. Cross-referencing the SIP `Request-URI` field confirms the domain `sip.callwithus.com` — an external commercial VoIP provider.

---

### Phase 4 — REGISTER Analysis & Credential Exposure

All REGISTER packets were extracted with source IP, calling extension, and authentication digest response:

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER" \
  -Tfields -e ip.src -e sip.from.user -e sip.auth.digest.response
```

**Result:** Extension `085499826` registered repeatedly from `192.168.10.15`. Multiple distinct MD5 digest responses were captured across the session, corresponding to separate authentication challenges from the server. The standard SIP Digest challenge-response flow (401 Unauthorized → REGISTER with credentials → 200 OK) was observed and repeated across the capture window.

> The MD5 digest responses are visible in cleartext within the UDP payload. While not directly reversible to the plaintext password, they are subject to offline dictionary and brute-force attacks if captured by an adversary on the same network segment. No TLS transport for SIP signaling was observed.

Sample REGISTER sequence observed:

| Frame | Direction | Status |
|-------|-----------|--------|
| 40 | Client → Server | REGISTER (1 binding) |
| 45 | Server → Client | 401 Unauthorized |
| 47 | Client → Server | REGISTER with digest (1 binding) |
| 51 | Server → Client | 200 OK |

---

### Phase 5 — Plaintext Message Interception

All SIP MESSAGE method packets were inspected in verbose mode:

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==MESSAGE" -V
```

**Result:** Multiple MESSAGE requests were sent to `+918108591527@sip.callwithus.com` (India). The message body, transmitted as `Content-Type: text/plain`, contained the string:

```
Dude test text
```

The full SIP frame (Frame 159) disclosed the following fields:

- **Source:** `192.168.10.15:55065`
- **Destination:** `208.51.63.146:5060`
- **From:** `sip:085499826@sip.callwithus.com`
- **To:** `sip:+918108591527@sip.callwithus.com`
- **Call-ID:** `zyOUBsEltl0p1Gm4_s9Ceg..`
- **CSeq:** 3 MESSAGE
- **Proxy-Auth:** Digest username `085499826`, realm `sip.callwithus.com`, MD5

The server responded with `407 Proxy Authentication Required` before ultimately accepting the message with `202 Accepted` (Frame 164).

> SIP MESSAGE content is transmitted in plaintext over UDP. Any passive observer on the network path between client and SIP server can read message content in full without decryption.

---

### Phase 6 — Call Reconstruction

To confirm which extensions completed a full call (i.e., a BYE packet was exchanged, proving the call was established and terminated normally):

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==BYE" \
  -Tfields -e sip.from.user -e sip.to.user
```

**Result:**

| From | To |
|------|----|
| 085499826 | +918108591527 |
| 085499826 | +918108591527 |

Two BYE packets were captured, confirming that extension `085499826` completed at least one voice call to `+918108591527`. The INVITE flow for the call to `18004190691` (observed in frames 2201+) showed repeated `500 Internal Server Error` and `408 Request Timeout` responses, indicating that call was never connected.

---

### Phase 7 — Codec Analysis

SDP media negotiation was extracted to identify audio codecs in use:

```bash
tshark -r VoIP_traffic.pcap -Y "sdp" -Tfields -e sdp.media
```

**Result:** Three distinct codec configurations were observed across SDP exchanges:

| SDP Media Line | Codecs (RTP Payload Types) |
|----------------|---------------------------|
| `audio 48268 RTP/AVP 3 0 8 101` | GSM (3), PCMU/G.711µ (0), PCMA/G.711A (8), DTMF (101) |
| `audio 19138 RTP/AVP 3 101` | GSM (3), DTMF (101) |
| `audio 22166 RTP/AVP 8 101` | PCMA/G.711A (8), DTMF (101) |

No SRTP (`RTP/SAVP`) was negotiated. All media streams used unencrypted RTP, meaning audio content is recoverable from the capture.

---

## Key Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | SIP signaling transmitted over UDP with no TLS — credentials and message content exposed in cleartext | Medium |
| 2 | MD5 digest authentication hashes captured across multiple REGISTER exchanges | Medium |
| 3 | Plaintext SIP MESSAGE content (`Dude test text`) fully visible in capture | Low |
| 4 | Voice call to international number (`+918108591527`, India CC 91) completed and confirmed via BYE | Informational |
| 5 | RTP media streams unencrypted — audio recovery from PCAP is feasible | Medium |
| 6 | Failed INVITE attempts to `18004190691` with repeated 500/408 responses — possible misconfigured dialing or server-side issue | Informational |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Network Sniffing | T1040 | Plaintext SIP/RTP traffic allows passive credential and content capture |
| Credentials from Network Protocols | T1557 | MD5 digest responses recoverable via offline attack |
| Exfiltration Over Alternative Protocol | T1048.003 | Data transmitted via SIP/RTP over UDP |

---

## IOC Summary

| Type | Value |
|------|-------|
| Internal IP | 192.168.10.15 |
| External SIP Server | 208.51.63.146 |
| SIP Domain | sip.callwithus.com |
| Extension | 085499826 |
| Called Number | +918108591527 |
| Called Number | 18004190691 |
| User-Agent | Zoiper r656527b |
| Call-ID | zyOUBsEltl0p1Gm4_s9Ceg.. |

---

## Recommendations

1. **Enforce SIP over TLS (SIPS)** on all VoIP endpoints — prevents plaintext credential and signaling exposure.
2. **Enforce SRTP** for media streams — prevents audio recovery from captured RTP.
3. **Review international dialing policy** — the completed call to India (`+918108591527`) should be verified as authorized.
4. **Audit SIP client versions** — Zoiper r656527b should be checked against current release to identify known vulnerabilities.
5. **Monitor for repeated REGISTER failures** — a pattern of 401 responses followed by digest retries on the same extension may indicate credential-stuffing attempts.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Tshark | CLI packet analysis and field extraction |
| Wireshark display filters | `sip`, `rtp`, `sdp`, `sip.Method`, `sip contains` |

---

*References: [Tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html) · [Wireshark](https://www.wireshark.org/)*

