# SOC Investigation Report
## Case ID: NTA-2024-HTTPS-001
## Network Traffic Analysis - Encrypted HTTPS Traffic Investigation

---

> **Classification:** TLP:WHITE - Portfolio / Training Exercise  
> **Analyst:** Miroslaw Lerch  
> **Platform:** AttackDefense Labs (PentesterAcademy)  
> **Lab:** Filtering Advanced: HTTPS  
> **Date:** 2026  
> **Status:** CLOSED - Analysis Complete

---

## Executive Summary

During a scheduled network traffic review exercise, a PCAP capture (`HTTPS_traffic.pcap`) containing encrypted HTTPS/TLS sessions was analyzed using `tshark` to extract actionable intelligence from encrypted traffic metadata. Although HTTPS encrypts the payload, significant forensic value remains accessible through TLS handshake metadata, DNS query patterns, certificate issuer fields, and behavioral fingerprinting.

This investigation demonstrates that **encrypted traffic is not opaque to a trained SOC analyst**. Through disciplined filtering and field extraction, the following was determined:

- Multiple SSL/TLS sessions to external servers were identified and mapped
- DNS resolution patterns revealed internal client behavior and server infrastructure
- Certificate issuer chains exposed the identity of contacted services
- Avast Antivirus traffic was identified across three internal hosts via behavioral fingerprinting
- The internal host `192.168.10.9` was confirmed as the sole user interacting with Ask Ubuntu servers

**No malicious activity was confirmed**, but the methodology applied here directly translates to threat hunting, C2 beacon detection, and encrypted malware traffic analysis.

---

## Threat Scenario

| Field | Value |
|---|---|
| Scenario Type | Network Forensics - Encrypted Traffic Analysis |
| Traffic Type | HTTPS / TLS 1.2 |
| Capture File | HTTPS_traffic.pcap |
| Analysis Tool | tshark (Wireshark CLI) |
| Environment | Internal LAN segment + external internet |
| Analyst Objective | Extract intelligence from encrypted traffic without decryption |

---

## Investigation Walkthrough

### Phase 1 — SSL/TLS Traffic Isolation

**Objective:** Isolate all SSL/TLS traffic from the full capture.

```bash
tshark -Y 'ssl' -r HTTPS_traffic.pcap
```

**Finding:** Packets containing TLS 1.2 sessions were returned, including `Client Hello`, `Server Hello`, `Certificate`, `Change Cipher Spec`, `Application Data`, and `Encrypted Alert` messages. This confirms active TLS sessions between internal hosts and external servers.

**Analyst Note:** Even without decrypting the payload, the TLS record types alone reveal session lifecycle — useful for detecting incomplete handshakes (potential scanning), unexpected `Encrypted Alert` messages (connection tears that may indicate detection evasion), and unusual handshake timing.

---

### Phase 2 — TLS Handshake Source/Destination Mapping

**Objective:** Map all endpoints participating in TLS handshakes.

```bash
tshark -r HTTPS_traffic.pcap -Y "ssl.handshake" -Tfields -e ip.src -e ip.dst
```

**Finding:** Multiple handshake pairs were identified between the internal host `192.168.0.136` and external IPs including:

| Source IP | Destination IP |
|---|---|
| 192.168.0.136 | 104.65.234.18 |
| 192.168.0.136 | 134.170.107.72 |
| 192.168.0.136 | 74.125.68.188 |
| 192.168.0.136 | 54.230.191.232 |

**Analyst Note:** Bidirectional handshake pairs are expected. A host initiating many TLS handshakes in a short window without corresponding DNS queries can indicate C2 beaconing to hardcoded IP addresses — a key threat hunting pivot.

---

### Phase 3 — Certificate Issuer Extraction

**Objective:** Identify the certificate authorities (CAs) and organizations behind the SSL sessions.

```bash
tshark -r HTTPS_traffic.pcap -Y "ssl.handshake.certificate" -Tfields -e x509sat.printableString
```

**Finding:** The following certificate issuers were extracted:

| Certificate Issuer Chain |
|---|
| Microsoft Corporation — Microsoft IT SSL SHA2 |
| Google Inc — Google Internet Authority G2 — GeoTrust |
| Symantec Class 3 Secure Server CA G4 — VeriSign Trust Network |
| DigiCert SHA2 High Assurance Server CA — Facebook, Inc. |
| DigiCert SHA2 Secure Server CA — Grammarly, Inc. |

**Analyst Note:** Certificate issuer extraction without decryption is a legitimate intelligence technique. In threat hunting, self-signed certificates, certificates issued by unknown CAs, or certificates with anomalous validity periods are high-fidelity indicators of malicious infrastructure. All issuers here are legitimate.

---

### Phase 4 — Server IP Enumeration via Client Hello

**Objective:** List all external servers the internal network established SSL connections to, using the Client Hello as the initiating signal.

```bash
tshark -r HTTPS_traffic.pcap -Y "ssl && ssl.handshake.type==1" -Tfields -e ip.dst
```

**Finding — SSL Server IPs:**

| Destination IP | Likely Owner (based on certificate) |
|---|---|
| 104.65.234.18 | Akamai CDN |
| 134.170.107.72 | Microsoft |
| 74.125.68.188 | Google |
| 54.230.191.232 | Amazon CloudFront |
| 31.13.78.35 | Facebook |
| 54.159.8.241 | Amazon AWS |
| 31.13.78.17 | Facebook |
| 157.240.191.17 | Facebook |
| 179.60.192.7 | Facebook |
| 119.81.94.2 | IBM / SoftLayer |

**Analyst Note:** The volume of Facebook IPs suggests a user was actively using Facebook at capture time. Repeated Client Hellos to the same IP without session reuse can indicate connection instability or automated tooling.

---

### Phase 5 — DNS Query Analysis

**Objective:** Identify DNS servers used by internal clients.

```bash
tshark -r HTTPS_traffic.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst
```

**Finding — DNS Servers Used:**

| DNS Server IP | Type |
|---|---|
| 192.168.0.1 | Internal gateway / likely SOHO router |
| 192.168.10.1 | Second internal subnet gateway |
| 8.8.8.8 | Google Public DNS |
| 8.8.4.4 | Google Public DNS (secondary) |

**Analyst Note:** Clients using Google's public DNS (8.8.8.8 / 8.8.4.4) directly — bypassing an internal DNS resolver — is a common threat hunting indicator. This behavior is used by malware to bypass DNS-based filtering and sinkholing. In an enterprise environment, direct external DNS queries should trigger a detection alert.

---

### Phase 6 — Ask Ubuntu Server Identification

**Objective:** Identify the IP addresses of Ask Ubuntu (askubuntu.com) servers and the internal user who contacted them.

```bash
tshark -r HTTPS_traffic.pcap -Y "ip contains askubuntu"
```

**Finding — Ask Ubuntu Server IPs:**

| IP Address | Role |
|---|---|
| 151.101.1.69 | Ask Ubuntu CDN node |
| 151.101.193.69 | Ask Ubuntu CDN node |
| 151.101.129.69 | Ask Ubuntu CDN node |
| 151.101.65.69 | Ask Ubuntu CDN node |

These IPs belong to Fastly CDN, which serves askubuntu.com as part of Stack Exchange's infrastructure.

**Client Identification:**

```bash
tshark -r HTTPS_traffic.pcap -Y "ip.dst==151.101.1.69 || ip.dst==151.101.193.69 || ip.dst==151.101.129.69 || ip.dst==151.101.65.69" -Tfields -e ip.src
```

**Result:** `192.168.10.9` — sole internal host querying Ask Ubuntu servers.

---

### Phase 7 — Antivirus Software Fingerprinting via Traffic Content

**Objective:** Identify hosts running Avast Antivirus through traffic content matching.

```bash
tshark -r HTTPS_traffic.pcap -Y "ip contains avast" -Tfields -e ip.src
```

**Finding — Hosts Running Avast:**

| Internal IP | Role |
|---|---|
| 192.168.10.9 | Internal workstation |
| 192.168.0.1 | Gateway (also running Avast agent) |
| 192.168.0.136 | Internal workstation |

**Analyst Note:** This technique — matching plaintext strings inside TLS traffic — works because some AV products embed their product name in HTTP User-Agent headers or beacon URLs that are resolved before full TLS negotiation. This same methodology is used by threat hunters to fingerprint software inventory passively, and by red teams to identify what AV is running on target hosts.

---

## IOC Table

| Type | Value | Context | Confidence |
|---|---|---|---|
| IPv4 — Internal | 192.168.0.136 | Primary TLS-communicating host | High |
| IPv4 — Internal | 192.168.10.9 | Queried askubuntu.com; running Avast | High |
| IPv4 — Internal | 192.168.0.1 | Internal gateway; Avast detected | Medium |
| IPv4 — External | 104.65.234.18 | TLS session target (Akamai) | Informational |
| IPv4 — External | 134.170.107.72 | TLS session target (Microsoft) | Informational |
| IPv4 — External | 74.125.68.188 | TLS session target (Google) | Informational |
| IPv4 — External | 54.230.191.232 | TLS session target (Amazon) | Informational |
| IPv4 — External | 151.101.1.69 | Ask Ubuntu / Fastly CDN | Informational |
| IPv4 — DNS | 8.8.8.8 | Direct external DNS usage | Low — Policy Violation |
| IPv4 — DNS | 8.8.4.4 | Direct external DNS usage | Low — Policy Violation |
| Certificate Issuer | DigiCert SHA2 / Facebook | TLS cert for Facebook sessions | Informational |
| Software | Avast Antivirus | Identified via traffic fingerprint | High |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Sub-Technique | Relevance to This Investigation |
|---|---|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS | Primary communication protocol observed |
| T1071.004 | Application Layer Protocol: DNS | — | DNS queries used for C2 resolution in real attacks; observed here for baseline |
| T1572 | Protocol Tunneling | — | HTTPS used to encapsulate all communications |
| T1040 | Network Sniffing | — | Analyst technique — passive traffic capture |
| T1016 | System Network Configuration Discovery | — | DNS server identification reveals network architecture |
| T1518.001 | Software Discovery: Security Software Discovery | — | Avast fingerprinting via traffic analysis |
| T1567 | Exfiltration Over Web Service | — | HTTPS as exfiltration channel in real incidents |

**Note:** No malicious TTPs were confirmed in this capture. The MITRE mapping reflects techniques that this investigation methodology detects and investigates.

---

## Detection Opportunities

### Detection Rule 1 — Direct External DNS (Policy Bypass)

**Logic:** Alert when an internal host sends DNS queries directly to external resolvers (not the corporate DNS server).

```
event_type: dns_query
AND src_ip: 192.168.0.0/8
AND dst_ip: NOT [approved_internal_dns_servers]
AND dst_port: 53
```

**Severity:** Medium  
**Use Case:** Malware bypassing DNS sinkholes; DNS tunneling to external C2

---

### Detection Rule 2 — Unusual TLS Certificate Issuer

**Logic:** Alert on TLS sessions presenting certificates from unknown or self-signed CAs.

```
event_type: tls_handshake
AND tls.cert_issuer: NOT [approved_ca_list]
OR tls.cert_self_signed: true
```

**Severity:** High  
**Use Case:** Malware C2 using self-signed certificates; MitM attacks

---

### Detection Rule 3 — High Volume Client Hello Without DNS Precedent

**Logic:** Alert on TLS Client Hello packets to IP addresses where no preceding DNS query was observed in the session window.

```
event_type: tls_client_hello
AND dst_ip: NOT IN [recently_resolved_ips]
AND timewindow: 60s
```

**Severity:** Medium  
**Use Case:** Hardcoded C2 IP addresses; DGA-resolved C2 where DNS was cached elsewhere

---

### Detection Rule 4 — Software Fingerprint via Network Traffic

**Logic:** Alert when traffic content matches known AV/EDR product strings for inventory auditing or anomaly detection.

```
event_type: network_content_match
AND content_match: ["avast", "eset", "sophos", "crowdstrike"]
AND src_ip: NOT IN [known_av_update_servers]
```

**Severity:** Informational  
**Use Case:** Passive software inventory; detecting unlicensed AV or unexpected software

---

## Incident Response Actions

> This exercise identified no active incident. The following actions reflect what would be taken if suspicious patterns were confirmed.

**Triage Priority 1:** Investigate direct external DNS usage on 8.8.8.8 / 8.8.4.4 — validate whether this is a policy exception or misconfiguration.

**Triage Priority 2:** Correlate the TLS session inventory with the approved application whitelist — flag any destination IPs not associated with known business applications.

**Triage Priority 3:** Validate Avast version and license status on `192.168.10.9`, `192.168.0.1`, and `192.168.0.136` — confirm AV is current and managed.

**Triage Priority 4:** Review `192.168.10.9` for additional indicators — this host made direct external DNS queries, accessed Ask Ubuntu, and ran Avast. Build a behavioral baseline.

---

## Containment / Eradication / Recovery

| Phase | Action | Priority |
|---|---|---|
| Containment | Block direct external DNS (port 53) at the firewall for all internal hosts except the approved internal resolver | High |
| Containment | Enforce DNS over the corporate resolver — all clients should use 192.168.0.1 or 192.168.10.1 | High |
| Eradication | N/A — no confirmed malicious activity | — |
| Recovery | Document approved external DNS exception list if 8.8.8.8 is authorized | Medium |
| Hardening | Implement TLS inspection (SSL inspection proxy) to enable payload visibility for corporate traffic | High |
| Hardening | Deploy certificate pinning monitoring — alert on unexpected cert issuer changes for critical business domains | Medium |

---

## Risk Assessment

| Risk Area | Current State | Risk Level | Recommendation |
|---|---|---|---|
| Direct external DNS | Observed — clients bypassing internal resolver | Medium | Enforce firewall block on outbound port 53 except from approved resolver |
| TLS visibility | Encrypted traffic not inspectable | Medium | Evaluate TLS inspection proxy deployment |
| Software inventory | AV identified passively — no active MDM confirmation | Low | Validate all hosts in MDM/EDR platform |
| Encrypted exfiltration | HTTPS can carry data exfiltration invisibly | Medium | Implement DLP at proxy layer; monitor for large HTTPS uploads |

---

## Lessons Learned

1. **Encrypted traffic is not blind traffic.** TLS handshake metadata — including certificate fields, handshake type, and timing — provides substantial intelligence without decryption.

2. **DNS is a forensic goldmine.** DNS query patterns reveal browsing behavior, software inventory, and potential policy violations. DNS logging should be mandatory in any SOC environment.

3. **String matching inside traffic works for passive fingerprinting.** The `ip contains` filter in tshark matched Avast beacon strings within network packets — this same technique detects malware C2 strings, credential harvesting domains, and data exfiltration markers.

4. **tshark field extraction enables scalable analysis.** Using `-Tfields -e field.name` transforms packet analysis into structured data that can feed into SIEM correlation, spreadsheet analysis, or automated IOC extraction pipelines.

5. **Direct external DNS is a detection opportunity.** In real environments, malware routinely uses 8.8.8.8 or 1.1.1.1 to bypass internal DNS monitoring. This should be a Sigma rule in every SOC.

---

## Skills Demonstrated

| Skill | Evidence |
|---|---|
| PCAP analysis with tshark | All 8 investigation commands |
| TLS/SSL protocol knowledge | Handshake type filtering, certificate extraction |
| DNS forensics | DNS flag filtering, resolver identification |
| Behavioral fingerprinting | Avast identification via content matching |
| Network IOC extraction | IP, certificate, and software IOC table |
| Threat hunting mindset | Detection rules derived from investigation findings |
| SOC documentation | Structured case file with MITRE mapping |
| Detection engineering | 4 actionable detection rules written |
| MITRE ATT&CK framework | 7 relevant techniques mapped |

---

## Tools Used

| Tool | Purpose |
|---|---|
| tshark | CLI-based PCAP analysis, field extraction, display filter application |
| Wireshark (reference) | Visual validation and filter syntax reference |
| MITRE ATT&CK Navigator | Technique mapping |
| AttackDefense Labs | Lab environment and PCAP source |

---

## GitHub Repository Structure

```
NTA-2024-HTTPS-001-HTTPS-Traffic-Analysis/
│
├── README.md                          ← This report
├── evidence/
│   └── (PCAP not included — lab environment only)
├── analysis/
│   ├── tshark_commands.md             ← All commands with explanations
│   ├── ioc_table.csv                  ← Machine-readable IOC export
│   └── dns_servers.txt                ← Extracted DNS resolver list
├── detections/
│   ├── direct_external_dns.yml        ← Sigma rule
│   ├── self_signed_tls_cert.yml       ← Sigma rule
│   └── c2_no_dns_precedent.yml        ← Sigma rule (pseudo)
├── screenshots/
│   ├── tshark_ssl_output.png
│   ├── handshake_ips.png
│   ├── certificate_issuers.png
│   ├── askubuntu_ips.png
│   └── avast_fingerprint.png
└── mitre/
    └── attack_navigator_layer.json    ← ATT&CK Navigator export
```

---

## Recruiter Summary

**What this project demonstrates:**

This investigation showcases my ability to conduct network forensics on encrypted HTTPS traffic using `tshark` — a core skill for SOC analysts and DFIR investigators. Rather than treating encrypted traffic as a dead end, I applied protocol-level knowledge to extract meaningful intelligence: endpoint mapping, certificate chain analysis, DNS behavior profiling, and passive software inventory via behavioral fingerprinting.

The project follows a real SOC case structure — from initial triage through IOC extraction, MITRE ATT&CK mapping, detection rule development, and documented IR recommendations — mirroring the workflow expected in an enterprise Blue Team environment.

**Directly relevant to:** SOC Analyst L1/L2, Blue Team Analyst, Network Forensics Analyst, DFIR Analyst

---

## LinkedIn Post

---

🔍 New portfolio project: Network Forensics on Encrypted HTTPS Traffic

One of the most common misconceptions in cybersecurity is that HTTPS means "nothing to see here."

As a SOC analyst, encrypted traffic is still full of intelligence — if you know where to look.

In this lab, I analyzed a PCAP file of HTTPS sessions using **tshark** and extracted:

✅ TLS handshake metadata mapping internal hosts to external servers  
✅ Certificate issuer chains (Microsoft, Google, Facebook, Grammarly, DigiCert)  
✅ DNS resolver behavior — including clients bypassing internal DNS with 8.8.8.8  
✅ IP addresses of Ask Ubuntu / Fastly CDN servers  
✅ Passive Avast Antivirus fingerprinting across 3 internal hosts via traffic content matching

No payload decryption needed.

The same techniques I used here apply directly to:
— Detecting C2 beacons using self-signed certificates  
— Identifying hardcoded C2 IPs (no DNS precedent = red flag)  
— Hunting for software running on endpoints without touching the host

Full write-up on GitHub: [link]

#SOCAnalyst #BlueTeam #DFIR #NetworkForensics #ThreatHunting #tshark #HTTPS #TLS #MITREAttack #Cybersecurity #CareerChange

---

*This project was completed as part of the AttackDefense / PentesterAcademy "Filtering Advanced: HTTPS" lab.*

---

**Analyst:** [Your Name]  
**Contact:** [LinkedIn / GitHub]  
**Date:** 2024  
**Classification:** TLP:WHITE

