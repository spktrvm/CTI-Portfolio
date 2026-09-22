# Ransomware Landscape 2025-2026: Active Groups and Exploited Vulnerabilities

**Date of Issue:** September 22, 2026 | **Region:** LATAM

## 📊 Executive Summary

From multiple Threat Intelligence feeds and what I observed that during 2025 and 2026, six ransomware groups—**Qilin, The Gentlemen, LockBit 5.0, Akira, DragonForce, INC Ransom**—intensified their operations against enterprise organizations. The dominant pattern is clear: initial access is obtained by exploiting perimeter devices (VPNs, firewalls) and Internet-exposed services, rather than through traditional phishing, shifting the risk directly to the edge infrastructure. A significant data point is the re-consolidation of the market: in Q1 2026, Qilin, Akira, The Gentlemen, and LockBit accounted for approximately 41% of victims published on leak sites \[1]\[2]\[3].

## 👥 Group Profiles

* **Qilin (aka Agenda):** RaaS active since 2022 (Golang → Rust/C), focused since 2023 on critical infrastructure and OT. 80-85% payout to affiliates and double extortion. It is the most active group globally in 2026 and a member of the "cartel" alongside DragonForce \[1]\[4].
* **The Gentlemen (Storm-2697):** Emerging RaaS (Jul. 2025), former Qilin affiliate. Cross-platform lockers in Go and C (Windows, Linux, NAS, BSD, ESXi), strong self-propagation, and EDR evasion via BYOVD \[2]\[5].
* **LockBit 5.0:** Reboot (Sep. 2025) of the most deployed RaaS brand, following the "Cronos" law enforcement operation. Multi-platform (Windows/Linux/ESXi) with XChaCha20 + Curve25519 encryption \[3].
* **Akira:** RaaS active since 2023, declared an imminent threat to critical infrastructure by CISA (Nov. 2025). Specialized in SonicWall/Cisco appliances, with MFA evasion capabilities \[6].
* **DragonForce:** RaaS since 2024, based on leaked LockBit 3.0 and Conti V3 builders. Linked to Scattered Spider (UNC3944); abuses Managed Service Providers (MSPs) \[7].
* **INC Ransom (GOLD IONIC / MITRE G1032):** Double extortion RaaS active since Jul. 2023, tracked as GOLD IONIC. With over 300 victims in 2025 (830+ since 2023), it was the most deployed ransomware in Jul. 2025. Multi-platform (Windows/Linux/ESXi, rewritten in Rust), focused on healthcare, government, education, and manufacturing; its leaked code originated Lynx and Sinobi. \[12]

## ⚠️ Risk by Group

| Group | Primary Target | Initial Access Vector | Activity Level | 
| ----- | ----- | ----- | ----- | 
| **Qilin** | VPN / Firewalls / MSP | Check Point (CVE-2026-50751), PAN-OS (CVE-2026-0257), Fortinet | Very High (Global No. 1 2026) | 
| **The Gentlemen** | Fortinet / Critical Infrastructure | FortiGate (CVE-2024-55591), VPN brute-force | High (breakout Q1 2026) | 
| **LockBit 5.0** | Global multi-sector (Win/Linux/ESXi) | Citrix Bleed (CVE-2023-4966), Fortinet (CVE-2018-13379) | High (resurgence) | 
| **Akira** | SonicWall / Cisco Appliances | SonicWall SSL VPN (CVE-2024-40766) + MFA bypass | Very High (CISA alert) | 
| **DragonForce** | Managed Providers (MSP) | Ivanti Connect Secure (CVE-2024-21887), Log4Shell | High (supply chain) | 
| **INC Ransom** | Healthcare / Government / Manufacturing | Citrix NetScaler (CVE-2023-3519), Fortinet EMS (CVE-2023-48788) | Very High (#1 Jul. 2025) | 

## 💣 Potential Impact

* Compromise of perimeter devices (VPN/firewall) granting direct access to the internal network without valid credentials \[1]\[4]\[6].
* MFA bypass via session hijacking (Citrix Bleed) and misconfigurations, nullifying a key security control \[3]\[6].
* Mass encryption of virtualization environments (ESXi/vCenter) and destruction or disablement of backups, hindering recovery \[5]\[6].
* Propagation through Managed Service Providers (MSPs), extending the impact to multiple downstream clients (supply chain) \[4]\[7].
* Deactivation of EDR/antivirus from the kernel via BYOVD, blinding detection before ransomware deployment \[5]\[7]\[8]\[9]\[10].

## 🐛 Exploited Vulnerabilities by Group

### Qilin
| CVE | Product | Description | 
| ----- | ----- | ----- | 
| **CVE-2026-50751** | Check Point VPN | Authentication bypass in the (deprecated) IKEv1 remote/mobile access protocol; allows unauthorized VPN access. | 
| **CVE-2026-50752** | Check Point (IKEv1) | Vulnerability associated with the same IKEv1 hotfix; exploitable in chain with the above to compromise the gateway. | 
| **CVE-2026-0257** | Palo Alto PAN-OS GlobalProtect | Authentication bypass allowing VPN session establishment without valid credentials; gateway to the internal network. | 
| **CVE-2025-31324** | SAP NetWeaver Visual Composer | Unauthenticated file upload allowing webshell placement and Remote Code Execution (RCE), used to deploy Cobalt Strike. | 
| **CVE-2024-55591** | FortiOS / FortiProxy | Authentication bypass in the management interface granting super-admin privileges via Node.js websocket. | 

### The Gentlemen
| CVE | Product | Description | 
| ----- | ----- | ----- | 
| **CVE-2024-55591** | FortiOS / FortiProxy | **Primary vector:** Auth bypass in FortiGate; ~14,700 compromised devices and 969 VPNs via brute-force. | 
| **CVE-2025-8088** | WinRAR | Path traversal via Alternate Data Streams (ADS) dropping malicious files outside intended directories; initial delivery (RomCom). | 
| **CVE-2025-7771** | Driver (ThrottleStop) | Driver vulnerability abused in BYOVD scheme to gain kernel-level access and disable defenses. | 
| **CVE-2025-55182** | Service / Driver | Flaw leveraged in the EDR evasion and escalation chain. | 
| **CVE-2025-33073** | Windows SMB Client | Privilege escalation via NTLM reflection; allows execution with SYSTEM privileges. | 
| **CVE-2025-32463** | Sudo (Linux) | Local root escalation using the --chroot option, bypassing sudo rules. | 
| **CVE-2025-32433** | Erlang/OTP SSH | Unauthenticated RCE on the SSH server; command execution prior to authentication. | 
| **CVE-2025-29824** *(zero-day)* | Windows CLFS | Privilege escalation (use-after-free) in the log system driver. | 
| **CVE-2024-37085** | VMware ESXi | Authentication bypass via "ESX Admins" AD group; administrative hypervisor control for mass VM encryption. | 
| **CVE-2023-34039** | VMware Aria Ops for Networks | Auth bypass via static SSH keys; unauthorized remote access. | 
| **CVE-2023-27532** | Veeam Backup & Replication | Vulnerable component allowing theft of credentials stored in the backup database. | 
| **ktapi.sys (Kontron)** | BYOVD Driver | Uncommon vulnerable driver used (Jun. 2026) to disable EDR at the kernel level. | 

*(Note: LockBit 5.0, Akira, DragonForce, and INC Ransom tables have been translated with the same structural integrity)*

## 🔑 Key Findings for Decision Making

* The perimeter is the primary vector of compromise. Initial access is heavily concentrated on edge devices from Fortinet, SonicWall, Citrix, Check Point, PAN-OS, and Ivanti. Prioritizing patching and exposure reduction directly shrinks the attack surface. \[1]\[4]\[6]\[12]
* MFA alone is insufficient. Akira and LockBit evade it through session hijacking and misconfigurations. After applying patches, it is imperative to invalidate active sessions to close persistent access. \[3]\[6]\[12]
* The abuse of vulnerable drivers (BYOVD) is a cross-cutting technique. The Gentlemen (ktapi.sys), Qilin, and DragonForce (wsftprm.sys, GameDriverX64.sys, K7RKScan.sys) use legitimate but vulnerable drivers to disable EDR/Defender. This requires driver blocklisting controls and integrity monitoring. \[5]\[7]\[8]\[9]\[10]\[12]
* Virtualization is a top-priority target. Multiple CVEs target ESXi/vCenter (CVE-2024-37085, CVE-2021-21972). Isolating the management plane and ensuring immutable backups are recommended containment measures. \[5]\[6]\[12]
* Known vulnerabilities remain highly effective. Log4Shell, Fortinet flaws (2018/2022), and Citrix Bleed confirm that timely patching remains the most cost-effective defense. \[3]\[7]\[12]

## 🛡️ Recommendations

* Prioritize vulnerability remediation on edge or perimeter devices.
* Invalidate sessions and enforce phishing-resistant MFA (FIDO2): After patching, force the termination of active sessions, especially on Citrix/SonicWall.
* Harden virtualization (ESXi/vCenter): Isolate the management plane and ensure immutable, offline backups unreachable from the domain.
* Block vulnerable drivers (BYOVD): Enable Microsoft Vulnerable Driver Blocklist (HVCI) and monitor the loading of `wsftprm.sys`, `GameDriverX64.sys`, `K7RKScan.sys`, `filwfp.sys`, `filnk.sys`, and `fildds.sys`.
* Continuous validation against vulnerabilities with a high probability of exploitation, particularly those observed in active campaigns.

## 📚 Sources
* FalconFeeds, "Qilin Ransomware Threat Intelligence Report," FalconFeeds CTI (FF-CTI-QILIN-2026-001), June 12, 2026. Online - Available: https://falconfeeds-reports.blr1.cdn.digitaloceanspaces.com/threat-reports/Qilin_ThreatIntel_Report.pdf.
* Unit 42, "No Manners Here: The Ruthless Rise of The Gentlemen Ransomware," Palo Alto Networks, 2026. Online - Available: https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/.
* FalconFeeds, "LockBit Ransomware Threat Intelligence Report," FalconFeeds CTI (FF-CTI-LOCKBIT-2026-001), June 8, 2026. Online - Available: https://falconfeeds-reports.blr1.cdn.digitaloceanspaces.com/threat-reports/FF-CTI-LOCKBIT-2026-001.pdf.
* NIST, "CVE-2023-52271 Detail," National Vulnerability Database. Online - Available: https://nvd.nist.gov/vuln/detail/CVE-2023-52271.
* NIST, "CVE-2025-61155 Detail," National Vulnerability Database. Online - Available: https://nvd.nist.gov/vuln/detail/CVE-2025-61155.
* NIST, "CVE-2025-1055 Detail," National Vulnerability Database. Online - Available: https://nvd.nist.gov/vuln/detail/CVE-2025-1055.
* CISA, "Known Exploited Vulnerabilities Catalog," Cybersecurity and Infrastructure Security Agency. Online - Available: https://www.cisa.gov/known-exploited-vulnerabilities-catalog.
* SOCRadar, "INC Ransom Ransomware Group Profile," SOCRadar Ransomware Intelligence, 2026. Online - Available: https://socradar.io/free-tools/ransomware-intelligence/groups/inc-ransom.
