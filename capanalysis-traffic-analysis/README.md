# Capanalysis Traffic Analysis

## Description
Traffic analysis using CapAnalysis.

## Tools
- CapAnalysis

## Findings
- QUIC was the dominant protocol 
- TOR traffic detected 
- BitTorrent and Dropbox activity observed 
- Amazon traffic identified
- Total traffic volume: 77.5 MB
- Highest traffic IP: 192.168.0.136 (25.4%)
- Traffic mainly destined to: USA

## Analysis
### Overview
The dataset "Challenge" consists of 2 capture files totalling 84.7 MB. Traffic is predominantly inbound (96% In / 4% Out), suggesting this network is primarily a consumer environment. The top 5 protocols identified were LLMNR (24.9%), DNS (22.6%), Other (21.0%), HTTP (13.6%), and SSDP (10.0%).

![Overview](overview.png)
### Flow
Traffic flows were analysed across countries and days. The dominant destination countries were the United States of America, India, and Japan. Two capture dates were identified: 2017-03-03 and 2016-06-20. The most significant protocols by data volume were QUIC and SSL, with notable flows to SSL.Facebook, SSL.Google, SSL.YouTube, and SSL.Amazon. TOR traffic was detected flowing to multiple countries, indicating potential anonymisation activity within the network.

![Flow](flow.png)
### IP Analysis
129 source IPs and 307 destination IPs were identified across 3.4K flows. The top source IPs by bytes sent were:

- 192.168.10.9 - 969.2K sent / 34.1M received
- 192.168.252.128 - 930.4K sent / 21M received
- 192.168.0.136 - 741.1K sent / 18.9M received

All three top IPs show significantly higher bytes received than sent, consistent with the 96% inbound traffic observation. IPs 192.168.0.1 and 192.168.0.165 show bytes sent with zero bytes received — potentially indicative of broadcast or one-way communication traffic.

![IP](ip.png)

## Lessons Learned
- Traffic analysis reveals protocols and behavior
- Even without payload, patterns are visible
- QUIC and SSL dominate modern web traffic, making deep packet inspection increasingly difficult without decryption capabilities
- TOR and BitTorrent detection highlights the importance of protocol-level analysis even without payload inspection
- High inbound traffic ratios can indicate a download-heavy environment or potential data exfiltration if unexpected
- Traffic destined primarily to the USA aligns with cloud service usage (Google, Amazon, Facebook, YouTube)
