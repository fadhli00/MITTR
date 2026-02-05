# Phase 4: Credential Access — SAM & LSASS Dumping

## Overview

**Objective**  
Obtain credential material from the compromised host to support privilege escalation and lateral movement. The attacker extracts password hashes and memory-resident credentials for offline cracking and credential reuse.

**MITRE ATT&CK Mapping**
- **Tactic:** TA0006 – Credential Access  
- **T1003.002:** Security Account Manager (SAM)  
- **T1003.001:** LSASS Memory  

**Strategy**  
Two realistic techniques are combined:
1. Offline hash extraction via SAM hive export  
2. In-memory credential dumping from LSASS  

---

## Scenario A — SAM Hive Extraction

**Analyst Context**  
The SAM database stores local password hashes. The SYSTEM hive provides the decryption key. Exporting both enables offline credential recovery without generating authentication noise.

---

## Attack Simulation (Red Team)

### Step 1: Hive Export

**Command**
```
reg save HKLM\SAM C:\Users\Public\sam.save
reg save HKLM\SYSTEM C:\Users\Public\system.save
```

**[Screenshot required]**

The attacker uses built-in Windows functionality to extract credential material.

---

## Detection & Hunting (Blue Team — Splunk)

**Detection Logic**  
Registry hive export targeting SAM/SYSTEM is a high-confidence credential theft signal.

**Query**
```
index=windows EventCode=1 
Image="*\\reg.exe"
CommandLine="*save*" AND (CommandLine="*HKLM\\SAM*" OR CommandLine="*HKLM\\SYSTEM*")
| table _time, ComputerName, User, CommandLine
```

**[Screenshot required]**

**Assessment**  
Manual export of credential hives has no legitimate operational purpose and indicates malicious activity.

---

## Endpoint Detection (Blue Team — LimaCharlie)

**Detection Trigger**  
Process telemetry identifies reg.exe exporting sensitive registry hives.

**[Screenshot required]**

**Assessment**  
Behavior aligns with credential harvesting prior to lateral movement.

---

## Scenario B — LSASS Memory Dumping

**Analyst Context**  
LSASS holds active credentials in memory. Dumping it exposes reusable passwords and authentication material.

---

## Attack Simulation (Red Team)

### Step 2: LSASS Dump via Comsvcs.dll

**Command**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Users\Public\lsass.dmp full
```

**[Screenshot required]**

A native Windows DLL is abused to create a credential dump without external tooling.

---

## Detection & Hunting (Blue Team — Splunk)

**Detection Logic**  
Use of rundll32 with MiniDump parameters strongly indicates LSASS dumping.

**Query**
```
index=windows EventCode=1
Image="*\\rundll32.exe"
CommandLine="*comsvcs.dll*MiniDump*"
| table _time, ComputerName, User, CommandLine
```

**[Screenshot required]**

**Assessment**  
Access to LSASS memory outside system processes signals credential theft.

---

## Endpoint Detection (Blue Team — LimaCharlie)

**Detection Trigger**  
Suspicious LSASS access and dump creation observed in endpoint telemetry.

**[Screenshot required]**

**Assessment**  
Confirms active post-exploitation credential harvesting.

---

## SOC Decision & Response

**Status:** CONFIRMED CREDENTIAL COMPROMISE

**Actions**
- Terminate suspicious processes  
- Isolate host  
- Reset affected credentials  
- Investigate follow-on authentication activity  

---

## Key Takeaway

Credential access was achieved using native Windows features without exploit kits or malware. Behavioral monitoring is essential to detect this form of stealth credential theft. This phase marks transition from access to credential control.

