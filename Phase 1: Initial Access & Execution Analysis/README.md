# Phase 1: Initial Access & Execution Analysis

## Project Overview

**Scenario:** Initial Access via User Execution  
**Perspective:** Red Team Simulation & Blue Team Detection  
**Environment:** Homelab SOC Simulation  

**Tools Used**
- **Sliver** — Command & Control (Attacker)
- **Splunk** — SIEM
- **LimaCharlie** — Endpoint Detection & Response (EDR)

---

## 1. Executive Summary

This phase simulates an adversary gaining an initial foothold within the environment through **user-assisted execution**.

A malicious Windows payload named **`invoicee.exe`** was delivered to a victim workstation. The user manually executed the file, resulting in the establishment of a **Command & Control (C2)** channel back to the attacker infrastructure.

### Objectives
- Detect execution of an **unsigned binary**
- Identify **C2 beaconing activity**
- Correlate endpoint and network telemetry
- Assess analyst decision-making

---

## 2. Attack Simulation (Red Team)

### Tooling
**C2 Framework:** Sliver

### Payload Generation
```bash
generate --http 192.168.1.101:80 --save /opt/invoicee.exe --os windows
```

📸 **Screenshot Placement**
```md
![Sliver payload generation command](screenshots/phase-1/sliver-payload-generation.png)
```
*Shows Sliver C2 payload creation and command execution.*

---

A malicious payload named **`invoicee.exe`** was generated and saved to `/opt/invoicee.exe`.

The filename was intentionally chosen to appear legitimate and familiar, increasing the likelihood of successful user execution through **social engineering**.

### Delivery Method
- Manual drag-and-drop into the victim’s **Downloads** folder

📸 **Screenshot Placement**
```md
![Malicious file in Downloads folder](screenshots/phase-1/malware-in-downloads.png)
```
*Shows invoicee.exe placed in the user Downloads directory.*

---

### Execution
- User manually double-clicked the file
- No exploitation or lateral movement was used

📸 **Screenshot Placement**
```md
![User executing invoicee.exe](screenshots/phase-1/user-execution.png)
```
*Demonstrates manual execution by the user.*

---

## 3. Technical Analysis (Blue Team)

### Step 1: Process Execution Detection

#### Observation

LimaCharlie EDR generated alerts indicating suspicious activity on the host:

- **Hostname:** `fadhli-pc.redgunn.local`
- Execution of an unsigned binary
- Execution path within the **Downloads** directory
- YARA detections in memory

📸 **Screenshot Placement**
```md
![LimaCharlie alert - suspicious execution](screenshots/phase-1/limacharlie-execution-alert.png)
```
*EDR alert showing suspicious process execution.*

---

The process tree shows:

- **Parent Process:** `explorer.exe`
- **Child Process:** `invoicee.exe`

📸 **Screenshot Placement**
```md
![Process tree showing explorer.exe spawning invoicee.exe](screenshots/phase-1/process-tree.png)
```
*Confirms manual user execution.*

---

#### Evidence Collected
- **File Path:**  
  ```
  C:\Users\FADWIN10\Downloads\invoicee.exe
  ```

---

### Step 2: File Hash Investigation (Threat Intelligence)

#### Action

The SOC analyst extracted the SHA256 hash from LimaCharlie telemetry and performed reputation analysis.

📸 **Screenshot Placement**
```md
![File hash from EDR telemetry](screenshots/phase-1/file-hash-extraction.png)
```
*Shows hash extraction from LimaCharlie.*

---

#### Artifacts
- **File Path:**  
  ```
  C:\Users\FADWIN10\Downloads\invoicee.exe
  ```
- **SHA256 Hash:**  
  ```
  019b1291301dcf37569e80f7db6848c42b76d0b12196609965090d69e471d968
  ```
- **Signer:** Unsigned / Unknown Publisher

---

#### Initial VirusTotal Check
- **Result:** 0 detections
- **Assessment:** No existing global reputation

📸 **Screenshot Placement**
```md
![VirusTotal zero detection result](screenshots/phase-1/virustotal-zero-detection.png)
```
*Initial VT scan showing no detections.*

---

**Analyst Assessment:**  
A zero-detection binary appearing in the user Downloads directory is classified as **highly suspicious** and indicative of:
- Custom-compiled malware
- Targeted payload
- Polymorphic or new dropper

---

#### Secondary VirusTotal Submission

The binary was manually uploaded to VirusTotal for deeper inspection.

- **Result:** CRITICAL  
- **Detection Rate:** 58 / 70 vendors

📸 **Screenshot Placement**
```md
![VirusTotal high detection result](screenshots/phase-1/virustotal-high-detection.png)
```
*Post-submission VT results confirming malware.*

---

**Analyst Conclusion:**  
The file is confirmed malicious with high confidence.

**Decision:** Escalate to containment.

- **Indicator Type:** Atomic Indicator  
- **Indicator Value:** Known Bad Hash

---

### Step 3: Network Beaconing & C2 Correlation

#### Observation

Immediately after execution, the process initiated outbound network communication.

- **Destination IP:** `192.168.1.101`
- **Port:** `80 (HTTP)`
- **Pattern:** Repeated outbound connections (Beaconing)

📸 **Screenshot Placement**
```md
![Outbound C2 beaconing traffic](screenshots/phase-1/c2-beaconing.png)
```
*Network telemetry showing C2 communication.*

---

This activity was observed through:
- LimaCharlie EDR network telemetry
- Splunk correlation logs

📸 **Screenshot Placement**
```md
![Splunk logs showing beaconing correlation](screenshots/phase-1/splunk-beaconing-correlation.png)
```
*SIEM correlation confirming C2 activity.*

---

#### Analyst Assessment

The consistent outbound pattern strongly matches **C2 beacon behavior**, confirming successful attacker communication.

---

## 4. Detection Logic

### 4.1 LimaCharlie EDR Rule

The following Detection & Response logic triggers on:

- Unsigned binaries
- Executed from user-writable directories
- Establishing outbound internet connections

📸 **Screenshot Placement**
```md
![LimaCharlie detection rule](screenshots/phase-1/edr-detection-rule.png)
```
*EDR rule logic used for detection.*

---

*(Rule logic intentionally omitted for brevity / OPSEC)*

---

## 5. Containment & Lessons Learned

### Containment Status: **Delayed**

**Reasoning:**  
The infected host was deliberately left active to observe:

- Phase 2 — Privilege Escalation
- Phase 3 — Persistence mechanisms

---

### Real-World Scenario

In a production environment:
- The endpoint w
