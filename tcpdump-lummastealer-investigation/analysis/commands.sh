#!/bin/bash
# ============================================================
# SOC Investigation: Lumma Stealer
# Case ID: SOC-2024-0529-001
# Analyst: mirolerch
# Date: 2024-05-29
# Tool: tcpdump
# ============================================================

# Q1 - Total packet count
tcpdump -r tcpdump_challenge.pcap --count

# Q2 - ICMP packet count
tcpdump icmp -r tcpdump_challenge.pcap --count
tcpdump -r tcpdump_challenge.pcap icmp | wc -l

# Q3 - Identify ICMP destination and ASN
tcpdump icmp -r tcpdump_challenge.pcap
whois -h whois.cymru.com " -v 172.67.72.15"
# Result: ASN 13335 - CLOUDFLARENET

# Q4 - HTTP POST requests
tcpdump -r tcpdump_challenge.pcap -n port 80 | grep -E "POST"
tcpdump -tt -r tcpdump_challenge.pcap | grep "POST"

# Q5 - Extract credentials from HTTP payload
tcpdump -tt -r tcpdump_challenge.pcap -A | grep "password"
tcpdump -r tcpdump_challenge.pcap -A | grep password
tcpdump -r tcpdump_challenge.pcap port 80 -A | grep password
# Result: username=bsmith&password=ilovecats9102

# Q6 - Identify well-known TCP ports
tcpdump -tt -r tcpdump_challenge.pcap -n tcp | cut -d " " -f 3 | cut -d "." -f 5 | sort | uniq -c | sort -nr
tcpdump -nn -r tcpdump_challenge.pcap -n tcp | cut -d " " -f 3 | cut -d "." -f 5 | sort | uniq | sort -n
tcpdump -nn -r tcpdump_challenge.pcap -n tcp | awk '{print $5}' | cut -d. -f5 | sort | uniq -c | sort -nr
# Result: port 80 (HTTP) and port 21 (FTP)

# Q7 - FTP credential brute-force analysis
tcpdump -nn -r tcpdump_challenge.pcap -A port 21 | grep -E 'USER|PASS'
tcpdump -nn -r tcpdump_challenge.pcap -A port 21 | grep -E 'USER|PASS|230|530'
tcpdump -nn -r tcpdump_challenge.pcap -X port 21 | grep -E 'USER|PASS|230|530'
tcpdump -A -r tcpdump_challenge.pcap port 21 | grep -i USER
tcpdump -A -r tcpdump_challenge.pcap port 21 | grep -i PASS
# 230 = Login successful | 530 = Authentication rejected
# Result: demo:password

# Q8 - FTP file retrieval
tcpdump -nn -A -r tcpdump_challenge.pcap port 21 | grep 'RETR'
tcpdump -A -r tcpdump_challenge.pcap port 21 | grep -i RETR
tcpdump -A -r tcpdump_challenge.pcap port 21 | grep -i LIST
# Result: RETR readme.txt

# Q9 - Malware identification via User-Agent
tcpdump -A -r tcpdump_challenge.pcap port 80 | grep -i "User-Agent"
tcpdump -A -r tcpdump_challenge.pcap port 80 | grep -i "User-Agent" | sort | uniq
tcpdump -nn -r tcpdump_challenge.pcap port 80 -A | grep 'User-Agent'
# Result: TeslaBrowser/5.5 = Lumma Stealer
# OSINT: https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma

# Q10 - C2 URL identification
tcpdump -A -r tcpdump_challenge.pcap port 80 | grep -B 10 "TeslaBrowser"
tcpdump -A -r tcpdump_challenge.pcap port 80 | grep -A 20 "/+zz0192lskaaa"
tcpdump -nn -r tcpdump_challenge.pcap port 80 -A
# Result: hxxps[://]t[.]me/+zz0192lskaaa

# Q11 - Bonus: YouTube video
tcpdump -nn -r tcpdump_challenge.pcap port 80 -A | grep youtube
tcpdump -nn -r tcpdump_challenge.pcap port 80 -A | grep "Location:"
# Result: https://www.youtube.com/watch?v=dQw4w9WgXcQ
# Rick Astley - Never Gonna Give You Up
