# Phase 3: Persistence (TA0003)

## Objective
The attacker installs mechanisms to **maintain access across system restarts (reboots)**.

**MITRE ATT&CK Techniques**
- **T1547.001** – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** – Scheduled Task/Job: Scheduled Task

---

## 🚩 Phase 3a: Registry Run Keys

### Scenario
The attacker adds an entry to the **HKCU Run registry key** to automatically execute the implant whenever the user logs in.

**Technique:** T1547.001 – Registry Run Keys

---

### 1. Red Team Action (Sliver / CMD)

Executed on the victim machine via a Sliver shell:

    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveUpdate" /t REG_SZ /d "C:\Users\FADWIN10\Music\invoicee.exe" /f

**Why this works**
- The `Run` key is one of the most common Windows persistence mechanisms.

**Stealth**
- The value name **OneDriveUpdate** blends in with legitimate software.

📸 **Screenshot to include**
- Sliver session showing successful `reg add` execution
- (Optional) Registry Editor showing `OneDriveUpdate` in HKCU Run key

---

### 2. Blue Team Detection – Splunk

**Log Source**
- Sysmon Event ID 1 (Process Creation)

**Splunk Query**

    index="Fadhli-PC" EventCode=1
    Image="*\\reg.exe"
    CommandLine="*add*" AND CommandLine="*\\Run*"
    | table _time, User, CommandLine, ParentImage

📸 **Screenshot to include**
- Splunk results table showing `reg.exe` modifying `CurrentVersion\Run`

---

### 3. LimaCharlie Detection

**Alert Details**
- Detection Name: Potential Persistence Attempt Via Run Keys Using Reg.EXE
- Source: refractionPOINT (Sigma rules)
- Event Trigger: NEW_PROCESS

**Rule Logic**

    op: and
    rules:
      - op: ends with
        path: event/FILE_PATH
        value: reg.exe
      - op: contains
        path: event/COMMAND_LINE
        value: \Software\Microsoft\Windows\CurrentVersion\Run

**SOC Analyst Assessment**
- High-fidelity alert
- Binary added from `C:\Users\FADWIN10\Music\`
- Confirmed malicious persistence

📸 **Screenshot to include**
- LimaCharlie alert details page

---

## 🚩 Phase 3b: Scheduled Tasks

### Scenario
The attacker creates a scheduled task to run the implant daily.

**Technique:** T1053.005 – Scheduled Task

---

### 1. Red Team Action (Sliver / CMD)

    schtasks /create /sc daily /tn "WindowsCacheCleanup" /tr "C:\Users\FADWIN10\Music\invoicee.exe" /st 00:00 /f

**Stealth**
- Task name mimics system maintenance

📸 **Screenshot to include**
- Sliver shell showing task creation

---

### 2. Blue Team Detection – Splunk

**Log Source**
- Sysmon Event ID 1

**Splunk Query**

    index=windows EventCode=1
    Image="*\\schtasks.exe"
    CommandLine="*/create*"
    | table _time, User, CommandLine, ParentImage

**Assessment**
- Task Name: WindowsCacheCleanup
- Payload in user Music directory
- Scheduled daily at midnight
- Confirmed malicious

📸 **Screenshot to include**
- Splunk query results

---

### 3. LimaCharlie Detection

**Alert Details**
- Detection Name: Scheduled Task Creation Via Schtasks.EXE
- Source: refractionPOINT
- Event Trigger: NEW_PROCESS

**Rule Logic**

    op: and
    rules:
      - op: ends with
        path: event/FILE_PATH
        value: schtasks.exe
      - op: contains
        path: event/COMMAND_LINE
        value: /create

**SOC Analyst Assessment**
- High-severity alert
- Task masquerades as system process
- Confirmed malicious

📸 **Screenshot to include**
- LimaCharlie scheduled task alert

---

## 🚩 Phase 3c: Startup Folder

### Scenario
The attacker drops the implant into the user's Startup folder.

**Technique:** T1547.001 – Startup Folder

---

### 1. Red Team Action (Sliver / CMD)

    copy "C:\Users\FADWIN10\Music\invoicee.exe" "C:\Users\FADWIN10\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Update.exe"

📸 **Screenshot to include**
- Sliver shell confirming file copy
- (Optional) Startup folder view in Explorer

---

### 2. Blue Team Detection – Splunk

**Log Source**
- Sysmon Event ID 1

**Splunk Query**

    index=windows EventCode=1
    Image="*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
    | table _time, User, CommandLine, ParentImage

**Evidence**
- Binary executed directly from Startup folder
- Triggered on user login
- Executed by explorer.exe

**Analyst Assessment**
- Rare for legitimate apps
- High-fidelity persistence indicator

📸 **Screenshot to include**
- Splunk event showing Update.exe execution

---

## 🛡️ SOC Decision & Response

**Status:** CONFIRMED INCIDENT – PERSISTENCE DETECTED

### Immediate Containment
- Scheduled task removed:

      schtasks /delete /tn "WindowsCacheCleanup" /f

- Registry Run key cleaned
- sliver.exe process terminated

📸 **Screenshot to include**
- Task deletion output
- Registry key removal

---

### Remediation
- Full Autoruns scan (Sysinternals autorunsc)
- User credential reset due to full compromise

---

### Next Steps
- Review for Lateral Movement (TA0008)
- Investigate potential access to Domain Controller

---

## ✅ Consistency Check
- MITRE techniques correctly mapped
- Payload path consistent across phases
- Red Team actions align with Splunk & LimaCharlie detections
- Clear attack → detect → respond narrative

**Portfolio Ready:** Suitable for GitHub homelab showcasing SOC detection & response maturity
