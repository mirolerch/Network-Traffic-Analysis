# SOC Investigation: Lumma Stealer Detection via Network Traffic Analysis

![Status](https://img.shields.io/badge/Status-Closed-green)
![Severity](https://img.shields.io/badge/Severity-Critical-red)
![Tool](https://img.shields.io/badge/Tool-tcpdump-blue)
![MITRE](https://img.shields.io/badge/MITRE-T1102.002%20|%20T1110.003%20|%20T1048.003-orange)

**Case ID:** SOC-2024-0529-001  
**Analyst:** mirolerch  
**Date:** 2024-05-29  
**Classification:** TLP:WHITE  
**Status:** Closed — Confirmed Malware Activity  
**Source:** TCM Security SOC101 — Network Security Challenge  

---

## Executive Summary

On 2024-05-29 at approximately 14:53 UTC, endpoint `10.0.2.10` at Astley Financial triggered multiple SOC detections consistent with an active **Lumma Stealer (LummaC2)** infection. Analysis of `tcpdump_challenge.pcap` (1,344 packets) using exclusively Linux CLI tools confirmed four distinct threat activities:

- **Lumma Stealer C2 beacon** — hardcoded user agent `TeslaBrowser/5.5` communicating with Telegram dead-drop resolver `t.me/+zz0192lskaaa`
- **FTP credential brute-force** against `194.108.117.16:21` — 5 attempts across rotating source ports, 1 successful login (`demo:password`)
- **Credential exfiltration** via HTTP POST — employee credentials `bsmith:ilovecats9102` transmitted in cleartext to `93.184.215.14:80`
- **ICMP reconnaissance** — 132 packets observed, including traffic to Cloudflare-fronted infrastructure (`172.67.72.15`, ASN 13335)

**Business Impact:** Active credential theft confirmed on a financial institution endpoint. One FTP session successfully authenticated. Employee credentials exfiltrated over unencrypted HTTP. Immediate containment required.

---

## Threat Scenario

> The SOC received an alert indicating abnormal behavior on endpoint `10.0.2.10`. Multiple detections fired simultaneously. As the on-call SOC Analyst at Astley Financial, you are handed a packet capture and tasked with determining what happened, how, and what to do next.

**Malware Family:** Lumma Stealer (LummaC2)  
**Type:** Information Stealer / Malware-as-a-Service (MaaS)  
**First Seen:** August 2022 (Russian-speaking cybercrime forums)  
**Threat Actor:** "Shamel" / alias "Lumma"  
**Targets:** Cryptocurrency wallets, 2FA browser extensions, stored browser credentials  
**Exfiltration Method:** HTTP POST using hardcoded user agent `TeslaBrowser/5.5`  
**C2 Discovery:** Telegram dead-drop resolver  
**Reference:** [Malpedia — win.lumma](https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma)

---

## Investigation Walkthrough

### Question 1 — Total Packet Count

**Objective:** Establish the scope of the capture.

```bash
tcpdump -r tcpdump_challenge.pcap --count
```

**Result:** `1344 packets`

1,344 packets is a manageable capture for full manual CLI review. No need for sampling.

---

### Question 2 — ICMP Packet Count

**Objective:** Identify reconnaissance or keep-alive activity via ICMP.

```bash
tcpdump icmp -r tcpdump_challenge.pcap --count
tcpdump -r tcpdump_challenge.pcap icmp | wc -l
```

**Result:** `132 ICMP packets`

132 ICMP packets is anomalous for a standard endpoint. Consistent with either host discovery sweeps or C2 keep-alive mechanisms.

---

### Question 3 — ASN of ICMP Destination

**Objective:** Identify who the endpoint was pinging.

```bash
tcpdump icmp -r tcpdump_challenge.pcap
whois -h whois.cymru.com " -v 172.67.72.15"
```

**Result:** `ASN 13335 — CLOUDFLARENET (Cloudflare, Inc.)`

Cloudflare commonly fronts legitimate services but is also widely used to mask malicious C2 infrastructure. Flagged for further investigation.

---

### Question 4 — HTTP POST Requests

**Objective:** Detect outbound data exfiltration attempts.

```bash
tcpdump -r tcpdump_challenge.pcap -n port 80 | grep -E "POST"
tcpdump -tt -r tcpdump_challenge.pcap | grep "POST"
```

**Result:** `1 HTTP POST request`
