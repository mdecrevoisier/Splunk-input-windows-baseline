# Splunk advanced input configuration file for Windows

## Project purpose
**Splunk-input-windows-baseline** provides a unique `input.conf` configuration file that enables advanced collection of Windows logs using the *Splunk Universal Forwarder* agent. However, it does not stick only to the `Security` event log as most of the online public sources. Instead, it provides the following **special features**:
* **Instant deployment** on any host, independently of its type or role: domain controller, server or workstation. This allows to not miss any event in case a specific role or feature is activated on a host and at the same time to simplify maintenance operations.
* **Allow list approach**: only known and necessary events are collected to limit license impact
* Coverage for more than **70 native event logs** (including `RDP, BitLocker, AppLocker, PowerShell, WinRM, Defender, Printer, NTLM, VHD, Firewall, OpenSSH, SYSMON, Scheduled tasks`).
* Coverage for more than **10 server roles event logs** (including `ADDS/Active Directory, ADCS/PKI, ADCS/OCSP, Exchange, SQL Server, DNS server, DHCP server, Hyper-V, ADFS, IIS web server, Docker, NPS Radius, AOVPN`).
* **Usability** of collected events in my [SIGMA detection rules](https://github.com/mdecrevoisier/SIGMA-detection-rules).
* Provides a description for each event ID as well as a **MITRE ATT&CK reference** (when applicable).
* Provides **DFIR capacities** in regards of RDP usage, proxy and network configuration changes, Microsoft Office security alerts, Windows updates, MSI packages execution, activation or deactivation of Windows features, VHD disk mount, private key access, group policy updates, time service, firewall configuration change, default file association change, connected networks, LDAP queries ...

## How to use the configuration file
The configuration file can be applied on any Windows host (Vista or higher) where the *Splunk Universal Forwarder* is deployed. Some remarks before deploying it:
* Specific input configuration related to Splunk stack (format, sourcetype, index, evt_resolve_ad_obj, start_from ...) has to be done by your operations team.
* Some inputs are currently set to `disabled = 1`. This is due to a lack of documentation, time, testing or just not found documentation. Once reliable information will be obtained, I will update the configuration. Improvements or suggestions are welcome!
* Some inputs are mark with `!!! EVENT LOG FILE DISABLED PER DEFAULT !!!`. This means that the event log is disabled per default and needs to be activated. This can be done manually or per GPO following the instructions from my project [Windows auditing baseline](https://github.com/mdecrevoisier/Windows-auditing-baseline).
* REGEX are built using the `renderXml = true` option. If you disabled it, they will stop working.
* A unique identifier is provided close to each category (except for the `Security` event log). This should allow you to easily retrieve more information about the event log or event ID in my [Windows mindmaps](https://github.com/mdecrevoisier/Microsoft-eventlog-mindmap) or [Windows auditing baseline](https://github.com/mdecrevoisier/Windows-auditing-baseline) projects.

## Configuration file
The configuration file can be found in the `splunk-windows-input` folder. 

# Out of scope
The following topcis are currently not in the scope of this project:
* Metrics collection (CPU, RAM, EPS, ...).
* Noise reduction (but suggestions are welcome !).
* Transformations or parsers
* Input configuration for log files, specially `Windows DNS Server debug, DHCP Server transactions, IIS weberserver transactions ...`
* Firewall filtering platform events (`IDs 5154, 5156, 5152...`). We recommend instead to use SYSMON `ID 3`.
* Network share access events (`IDs 5140 and 5145`). We recommend instead to use SYSMON `ID 18`. (named pipes)


# Sources
The following sources were used to elaborate the configuration file:
* **Event log mindmap**: https://github.com/mdecrevoisier/Microsoft-eventlog-mindmap
* **Palantir WEF/WEC**: https://github.com/palantir/windows-event-forwarding
* **Notable events**: https://github.com/TonyPhipps/SIEM/blob/master/Notable-Event-IDs.md#microsoft-windows-winrmoperational
* **Event forwarding guidance**: https://github.com/nsacyber/Event-Forwarding-Guidance/blob/master/Events/README.md
* **NSA guidance**: https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf
* **Awesome event IDs**: https://github.com/stuhli/awesome-event-ids
* **Forensic goodness**: https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
* **ANSSI auditing guide**: https://www.ssi.gouv.fr/guide/recommandations-de-securite-pour-la-journalisation-des-systemes-microsoft-windows-en-environnement-active-directory/
* **Audit policy auditing and events**: https://docs.google.com/spreadsheets/d/e/2PACX-1vSD5-83wlU_GwI5Vz4cXhiwZr3QBqCh6VZSAigq8vHakf0UN4DF5SCpKXQm9YdGwIz_rNFBgYoMEIVl/pubhtml
* **Audit policy best practices**: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
* **Logging essentials**: https://github.com/JSCU-NL/logging-essentials/blob/main/WindowsEventLogging.adoc
* **Windows 10 event manifest**: https://github.com/repnz/etw-providers-docs/tree/master/Manifests-Win10-17134
* **Windows event ID mapping**: https://github.com/JSCU-NL/logging-essentials/blob/main/WindowsEventIDMapping.json
* **Windows events auditing per subcategory**: https://girl-germs.com/?p=363
* **Joint Sigint Cyber Unit logging essential**: https://github.com/JSCU-NL/logging-essentials/blob/main/WindowsEventLogging.adoc#account-activity
* **Windows 10 & Windows 11 changes in eventlog**: https://github.com/AndrewRathbun/SANSGoldPaperResearch_FOR500_Rathbun/tree/main/EventLogs 
