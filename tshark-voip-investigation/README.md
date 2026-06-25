# Network Traffic Analysis Report

**Report Title:** VoIP Traffic Analysis  
**Analysis Type:** Network Traffic Analysis · Tshark · VoIP  
**Analyst:** Miro Lerch  
**Date:** 2024-06-16  
**Status:** Closed

---

## Overview

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

### Show VoIP Traffic

VoIP traffic besteht aus zwei Protokollen: SIP übernimmt die Signalisierung (Verbindungsaufbau, Registrierung), RTP trägt den Audio-Stream. Mit `sip or rtp` werden beide kombiniert und alle VoIP-relevanten Pakete angezeigt.

```bash
tshark -r VoIP_traffic.pcap -Y "sip or rtp"
```

![VoIP Traffic](screenshots/01_VoIP_traffic.png)

---

### Print All REGISTER Packets

REGISTER ist die SIP-Methode, mit der ein Client seinen aktuellen Standort beim SIP-Server anmeldet. Durch Filtern auf diese Methode werden alle Registrierungsversuche im Capture sichtbar.

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER"
```

![REGISTER Packets](screenshots/02_register.png)

---

### Source IP, Sender Extension & Auth Digest Response

`-Tfields -e` extrahiert gezielt einzelne Felder als Spalten. Der Digest Response ist der MD5-Hash, den der Client zur Authentifizierung gegen den SIP-Server sendet.

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

![Digest Response](screenshots/03_digest_response.png)

---

### Codecs Used by RTP Protocol

SDP (Session Description Protocol) ist in SIP-Paketen eingebettet und handelt die Audio-Codecs sowie Ports für den RTP-Stream aus. Der Filter `sdp` mit dem Feld `sdp.media` zeigt alle angebotenen Codecs.

```bash
tshark -r VoIP_traffic.pcap -Y "sdp" -Tfields -e sdp.media
```

**Result:**

| SDP Media Line |
|----------------|
| audio 48268 RTP/AVP 3 0 8 101 |
| audio 19138 RTP/AVP 3 101 |
| audio 22166 RTP/AVP 8 101 |

![RTP Codecs](screenshots/04_rtp_codecs.png)

---

### IP Address of Zoiper VoIP Client

`sip contains` führt einen Substring-Match gegen den gesamten SIP-Payload durch. Das User-Agent-Feld in SIP-Headern identifiziert die Client-Software — hier Zoiper.

```bash
tshark -r VoIP_traffic.pcap -Y "sip contains Zoiper" -Tfields -e ip.src
```

**Result:** `192.168.10.15`

![Zoiper VoIP Client](screenshots/05__Zoiper_VoIP.png)

---

### IP Address of SIP Server

REGISTER-Pakete werden immer vom Client zum SIP-Server gesendet. Die Ziel-IP dieser Pakete identifiziert den Server.

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==REGISTER" -Tfields -e ip.dst
```

**Result:** `208.51.63.146`

---

### Content of Text Message Sent to +918108591527

Die SIP-Methode MESSAGE überträgt Sofortnachrichten über SIP. `-V` gibt das vollständig dekodierte Paket aus, einschließlich des Nachrichteninhalts im Klartext.

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method == MESSAGE" -V
```

**Result:** `Dude test text`

![Send Message I](screenshots/06__send_message_I.png)

![Send Message II](screenshots/07__send_message_II.png)

---

### Extensions That Completed a Call Successfully

Ein BYE-Paket wird nur gesendet, wenn ein Anruf erfolgreich aufgebaut und dann beendet wurde. Durch Filtern auf BYE und Extrahieren der From/To-Felder werden die Extensions sichtbar, die einen vollständigen Call abgeschlossen haben.

```bash
tshark -r VoIP_traffic.pcap -Y "sip.Method==BYE" \
  -Tfields -e sip.from.user -e sip.to.user
```

**Result:**

| From | To |
|------|----|
| 085499826 | +918108591527 |

![Call Extension](screenshots/08_call_extension.png)

---

## Summary

The capture file `VoIP_traffic.pcap` contained VoIP traffic between internal host `192.168.10.15` (Zoiper client) and external SIP server `208.51.63.146`. Extension `085499826` registered multiple times against the server and sent a plaintext SIP MESSAGE (`Dude test text`) to `+918108591527`. A successful voice call between `085499826` and `+918108591527` was confirmed via BYE packet. Audio codecs negotiated via SDP included PCMU, PCMA, GSM and DTMF (payload types 0, 3, 8, 101).

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Tshark | CLI packet analysis and field extraction |

---

*References: [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) · [Wireshark](https://www.wireshark.org/)*
