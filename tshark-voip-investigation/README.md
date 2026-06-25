# VoIP Traffic Analysis — Tshark

**Report Title:** VoIP Traffic Analysis  
**Analysis Type:** Network Traffic Analysis · Tshark · VoIP  
**Analyst:** Miro Lerch  
**Date:** 2024-06-16  
**Status:** Closed

---

## Executive Summary

A packet capture (`VoIP_traffic.pcap`) was analyzed to identify VoIP traffic, registered clients, SIP server infrastructure, and message content. Analysis was performed using Tshark with targeted SIP and RTP display filters.

---

## Threat Summary

| Field | Value |
|-------|-------|
| **Capture file** | `VoIP_traffic.pcap` |
| **Protocols** | SIP / RTP |
| **Client IP (Zoiper)** | 192.168.10.15 |
| **SIP server IP** | 208.51.63.146 |
| **Sending extension** | 085499826 |
| **Called number** | +918108591527 |
| **Message content** | Dude test text |
| **Extensions (completed call)** | 085499826 → +918108591527 |

---

## Analysis

### Task 1 — Show VoIP Traffic

```bash
tshark -r VoIP_traffic.pcap -Y "sip or rtp"
```

Filtered all SIP and RTP packets from the capture to display VoIP traffic only.

---

### Task 2 — Print All REGISTER Packets

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER"
```

Displayed all SIP REGISTER requests from the capture.

---

### Task 3 — Source IP, Sender Extension & Auth Digest Response

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER" \
  -Tfields -e ip.src -e sip.from.user -e sip.auth.digest.response
```

**Result:**

| Source IP | Extension | Digest Response |
|-----------|-----------|-----------------|
| 192.168.10.15 | 085499826 | bd7f2f715fe1826a48685cfb93d975c0 |
| 192.168.10.15 | 085499826 | 98d191fe9c3f4f9850bddea78667c653 |
| 192.168.10.15 | 085499826 | a0f880a2672c6d49cdd1fa1f10a3b2bd |
| 192.168.10.15 | 085499826 | 236528b2bd68c19333f7df926e17002e |

---

### Task 4 — Codecs Used by RTP Protocol

```bash
tshark -r VoIP_traffic.pcap -Y "sdp" -Tfields -e sdp.media
```

**Result:**

| SDP Media Line |
|----------------|
| audio 48268 RTP/AVP 3 0 8 101 |
| audio 19138 RTP/AVP 3 101 |
| audio 22166 RTP/AVP 8 101 |

---

### Task 5 — IP Address of Zoiper VoIP Client

```bash
tshark -r VoIP_traffic.pcap -Y "sip contains Zoiper" -Tfields -e ip.src
```

**Result:** `192.168.10.15`

---

### Task 6 — IP Address of SIP Server

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER" -Tfields -e ip.dst
```

**Result:** `208.51.63.146`

---

### Task 7 — Content of Text Message Sent to +918108591527

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method == MESSAGE" -V
```

**Result:** `Dude test text`

---

### Task 8 — Extensions That Completed a Call Successfully

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==BYE" \
  -Tfields -e sip.from.user -e sip.to.user
```

**Result:**

| From | To |
|------|----|
| 085499826 | +918108591527 |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Tshark | CLI packet analysis and field extraction |

---

*References: [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) · [Wireshark](https://www.wireshark.org/)*
