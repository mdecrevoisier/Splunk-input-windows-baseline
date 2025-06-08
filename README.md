# Splunk advanced input configuration for Windows

## Project goal
**Splunk-input-windows-baseline** provides a unique `input.conf` configuration file that enables Windows advanced log collection based on the MITRE ATT&CK framework using the *Splunk Universal Forwarder* agent.
![](/pictures/mitre.png)

## Project features
Conversely to a lot of online resources, this configuration does not stick only to the `Security` event log and does not follow Microsoft [very generic policies](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) for Windows or for [Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference). Indeed, it was designed by a threat detection analyst with a precise approach to collect only what is relevant in regards of **detection, threat hunting, incident response and forensic** purposes. Besides others things, it provides the following **key features**:
* **Instant deployment** on any server, independently of its type or role. This allows to not miss any event in case a specific role or feature is activated and at the same time to simplify maintenance operations. For workstations, some minor adjustments may need to be performed depending on your environment.
* **Allow list approach**: only known and necessary event IDs or providers are collected to limit license impact.
* **Description** for each event ID together with its **MITRE ATT&CK** TTP mapping (when applicable).
* Coverage for more than **70 native event logs** (including `Security, RDP, BitLocker, AppLocker, PowerShell, WinRM, Defender, Printer, NTLM, VHD, Firewall, OpenSSH, SYSMON, Scheduled tasks`).
* Coverage for more than **10 server roles or applications** (including `ADDS/Active Directory, ADCS/PKI, ADCS/OCSP, Exchange, SQL Server, DNS server, DHCP server, Hyper-V, ADFS, IIS web server, Docker, NPS Radius, AOVPN`).
* **Usability** of collected events within my [SIGMA detection rules](https://github.com/mdecrevoisier/SIGMA-detection-rules).
* Native **DFIR capacities** in regards of *RDP usage, proxy and network configuration changes, Microsoft Office security alerts, Windows updates, MSI packages execution, activation or deactivation of Windows features, VHD disk mount, private key access, group policy updates, time service, firewall configuration change, default file association change, connected networks, LDAP queries ...*

## Configuration file
The configuration file can be applied on any Windows host (Vista or higher) where the *Splunk Universal Forwarder* is deployed. 

### Configuration file remarks
* Specific input configuration related to Splunk stack (`format, sourcetype, index, evt_resolve_ad_obj, start_from ...`) has to be done by your operations team.
* Some stanzas are currently set to `disabled = 1`. This is due to a lack of documentation, time, testing or just not found documentation. Once reliable information will be obtained, I will update the configuration. Improvements or suggestions are welcome!
* Some stanzas are marked with `!!! EVENT LOG FILE DISABLED PER DEFAULT !!!`. This means that the event log is disabled per default and needs to be activated. This can be done manually or per GPO following the instructions from my project [Windows auditing baseline](https://github.com/mdecrevoisier/Windows-auditing-baseline).
* Whitelists and blacklists are built using the `renderXml = true` option. If you disabled it, they will stop working.
* A unique identifier is provided next to each category (except for the `Security` event log). This allows you to easily retrieve more information about the event log or event ID from my [Windows mindmaps](https://github.com/mdecrevoisier/Microsoft-eventlog-mindmap) or [Windows auditing baseline](https://github.com/mdecrevoisier/Windows-auditing-baseline) projects.

### Configuration file path
The configuration file can be found in the `splunk-windows-input` folder. 

## Out of scope / exclusions
The following topics or events are currently not in the scope of this project:

#### Splunk related
* Metrics collection (CPU, RAM, EPS ...).
* Noise reduction (but suggestions are welcome !).
* Input configuration for log files (e.g.: `Windows DNS Server debug, DHCP Server transactions, IIS web server transactions, PowerShell transcript ...`)

#### Windows event IDs related
* Firewall filtering platform events (`IDs 5154, 5156, 5152...`) which are very noisy. I recommend instead to use SYSMON `ID 3`.
* Network share access events (`IDs 5140, 5145`) which are very noisy. I recommend instead to use SYSMON `ID 17/18` (named pipes).
* Success NTLM login events (`ID 4776`) which are very noisy. Instead I just collect the failed ones.
* NTLM events (`8001, 8002, 8003, 8004`) which can be very noisy. Instead I suggest to use them only when necessary.
* Classic PowerShell events (`ID 600 and 800`) which are very noisy. Instead I only collect modern PowerShell events `ID 4103/4104`.
* Permissions changed on object (`ID 4670: File System, Registry, Authentication Policy and Authorization Policy`). These events are very noisy and instead I suggest to rather focus on the offensive actions (PowerShell, Command excecution...) that could trigger these permissions changes.

## Sources
The following sources were used to elaborate the configuration file:
* **Event log mindmap**: https://github.com/mdecrevoisier/Microsoft-eventlog-mindmap
* **Palantir WEF/WEC**: https://github.com/palantir/windows-event-forwarding
* **Notable events**: https://github.com/TonyPhipps/SIEM/blob/master/Notable-Event-IDs.md#microsoft-windows-winrmoperational
* **Yamato** tool suite: https://github.com/Yamato-Security
* **Event forwarding guidance**: https://github.com/nsacyber/Event-Forwarding-Guidance/blob/master/Events/README.md
* **NSA guidance**: https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf
* **Awesome event IDs**: https://github.com/stuhli/awesome-event-ids
* **Forensic goodness**: https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
* **ANSSI auditing guide**: https://www.ssi.gouv.fr/guide/recommandations-de-securite-pour-la-journalisation-des-systemes-microsoft-windows-en-environnement-active-directory/
* **Audit policy auditing and events** (from Florian ROTH): https://docs.google.com/spreadsheets/d/e/2PACX-1vSD5-83wlU_GwI5Vz4cXhiwZr3QBqCh6VZSAigq8vHakf0UN4DF5SCpKXQm9YdGwIz_rNFBgYoMEIVl/pubhtml
* **Audit policy best practices**: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
* **Logging essentials**: https://github.com/JSCU-NL/logging-essentials/blob/main/WindowsEventLogging.adoc
* **Windows 10 event manifest**: https://github.com/repnz/etw-providers-docs/tree/master/Manifests-Win10-17134
* **Windows event ID mapping**: https://github.com/JSCU-NL/logging-essentials/blob/main/WindowsEventIDMapping.json
* **Joint Sigint Cyber Unit logging essential**: https://github.com/JSCU-NL/logging-essentials/blob/main/WindowsEventLogging.adoc#account-activity
* **Windows 10 & Windows 11 changes in eventlog**: https://github.com/AndrewRathbun/SANSGoldPaperResearch_FOR500_Rathbun/tree/main/EventLogs 
* **MITRE Sensor mapping**: https://center-for-threat-informed-defense.github.io/sensor-mappings-to-attack/levels/mapping_winevtx/