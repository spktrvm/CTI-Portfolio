# Threat Intelligence Report: ENCFORGE Ransomware

## Executive Summary
ENCFORGE represents a significant tactical evolution in the ransomware landscape, marking a shift toward surgically targeting Artificial Intelligence (AI) and Machine Learning (ML) infrastructure. Deployed by the threat actor **JADEPUFFER**, this compiled Go ransomware is designed to encrypt critical AI assets, including model weights, vector databases, and training pipelines, bypassing traditional IT assets to maximize disruption in AI production environments.

## Threat Actor Profile: JADEPUFFER
* **Characteristics:** Highly adaptable, utilizes AI-driven agents to automate attack flows and correct execution failures in real-time.
* **Motivation:** Financial extortion and data destruction.
* **Previous Activity:** Known for data destruction campaigns targeting Alibaba's Nacos configuration servers and production databases using throwaway Python scripts.

## Attack Flow & Technical Analysis

### 1. Initial Access
The attack leverages external attack surface vulnerabilities rather than social engineering. The entry point is **CVE-2025-3248** (CVSS 9.8), an unauthenticated Remote Code Execution (RCE) flaw in Langflow versions prior to 1.3.0. The attacker exploits the exposed `/api/v1/validate/code` endpoint to execute arbitrary Python code on the server.

### 2. Container Breakout & Privilege Escalation
Once inside the Langflow container, the JADEPUFFER automated agent searches for the Docker socket (`/var/run/docker.sock`). Upon finding it, the agent dynamically generates and refines base64-encoded Python scripts (avoiding simple shell-level string detections) to interact with the Docker API. 

It deploys a new privileged container configured with:
* `Privileged: true`
* `PidMode: host`
* `NetworkMode: host`
* Root filesystem bind-mounted with read-write permissions.

Using `nsenter`, the attacker breaks out of the container namespace to execute commands directly on the underlying host.

### 3. Payload Delivery & Execution (ENCFORGE)
The payload is fetched from a Google Cloud Platform (GCP) C2 server and saved as `/.lockd` (using a leading dot to hide from standard directory listings). 

**Technical specifications of ENCFORGE:**
* **Architecture:** Static Go 1.22.12 ELF binary, packed with UPX 5.20.
* **Targeting:** It searches for approximately 180 specific file extensions related to AI/ML infrastructure, including:
  * PyTorch/TensorFlow checkpoints (`.ckpt`, `.pt`)
  * Hugging Face SafeTensors (`.safetensors`)
  * Local LLM standards (`.gguf`, `.ggml`)
  * Vector indexes (FAISS) and Training datasets (Parquet, Arrow).
* **Encryption Scheme:** Uses AES-256-CTR for fast, partial-file encryption (similar to LockBit/BlackCat routines), with the symmetric key wrapped by an embedded RSA-2048 public key.
* **Evasion & Impact:** Kills processes holding target files open, appends the `.locked` extension, drops ransom notes, and finally deletes itself from the host to hinder forensic analysis. It contains **no exfiltration capabilities**; leverage relies entirely on the destruction of the models.

---

## MITRE ATT&CK TTPs Mapping

| Tactic | Technique | ID | Description / Implementation |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Exploit Public-Facing Application | T1190 | Exploitation of CVE-2025-3248 in Langflow via the `/api/v1/validate/code` endpoint. |
| **Execution** | Command and Scripting Interpreter: Python | T1059.006 | Execution of dynamic, base64-encoded Python scripts to interact with the Docker API. |
| **Execution** | Container Administration Command | T1609 | Use of the Docker API via the exposed socket to spin up a malicious container. |
| **Privilege Escalation** | Escape to Host | T1611 | Mounting the host root filesystem and using `nsenter` to escape the container boundary. |
| **Defense Evasion** | Hide Artifacts: Hidden Files and Directories | T1564.001 | Dropping the ransomware payload on the host with a leading dot (`/.lockd`). |
| **Defense Evasion** | Obfuscated Files or Information: Software Packing | T1027.002 | The ENCFORGE binary is packed using UPX 5.20 to evade static signature detection. |
| **Defense Evasion** | Indicator Removal: File Deletion | T1070.004 | The ransomware deletes its own binary after the encryption routine completes. |
| **Discovery** | Container and Resource Discovery | T1613 | Sweeping the initial container environment to locate credentials and `/var/run/docker.sock`. |
| **Impact** | Service Stop | T1489 | Terminating processes that hold targeted AI/ML files open to ensure successful encryption. |
| **Impact** | Data Encrypted for Impact | T1486 | Encrypting model weights, vector databases, and datasets using AES-256-CTR. |

---

## Indicators of Compromise (IoCs)

### Files & Hashes
* **SHA-256 (Packed):** `8cb0c223b018cecef1d990ec81c67b826eb3c30d54f06193cf69969e9a8baea2`
* **SHA-256 (Unpacked):** `ea7822eac6cecef7746c606b862b4d3034856caf754c4cf69533662637905328`
* **File Names/Paths:** `/.lockd`
* **Encrypted File Extension:** `.locked`
* **Ransom Notes:** `README`, `HOW_TO_DECRYPT`, `README_DECRYPT`

### Attacker Infrastructure & Contact
* **Extortion Email:** `e78393397@proton.me`
* **Internal Go Project Strings:** `encfile` (ransomware binary), `keyforge` (keygen tool)

---

## Mitigation & Detection Strategies

1. **Vulnerability Management:** Upgrade Langflow immediately to version 1.9.1 or higher to patch CVE-2025-3248, CVE-2026-33017, and CVE-2026-55255. 
2. **Container Security:** 
   * Strictly restrict access to `/var/run/docker.sock`. Treat any unproxied exposure in application containers as a critical misconfiguration.
   * Implement runtime container security to alert on containers spun up with `Privileged: true` or `PidMode: host`.
3. **Infrastructure Resilience:** Treat AI model artifacts, training datasets, and vector databases as critical Tier-1 assets. Implement offline, immutable backups for all `.gguf`, `.safetensors`, `.pt`, and `.parquet` files.
4. **Credential Rotation:** Assume any API keys, database secrets, or cloud credentials present in compromised Langflow instances are burnt; rotate them immediately.
