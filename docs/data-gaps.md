# ATT&CK Data Source Gaps — Living Document

This document tracks known gaps between ATT&CK data source requirements and LimaCharlie's native telemetry capabilities. Updated as new data sources become available or new ATT&CK versions introduce additional requirements.

## Current Coverage Summary

LimaCharlie natively provides telemetry for these ATT&CK data component categories:

| Category | LC Coverage | Key Events |
|----------|-------------|------------|
| Process monitoring | Strong | NEW_PROCESS, EXEC_OOB |
| File system | Strong | FILE_CREATE, FILE_MODIFIED, FILE_DELETE |
| Registry (Windows) | Strong | REGISTRY_CREATE, REGISTRY_WRITE, REGISTRY_DELETE |
| Network connections | Good | NEW_TCP4_CONNECTION, NEW_TCP6_CONNECTION, NEW_UDP4_CONNECTION, DNS_REQUEST |
| Module/DLL loading | Good | MODULE_LOAD, CODE_IDENTITY, HIDDEN_MODULE_DETECTED |
| Service monitoring | Good | SERVICE_CHANGE |
| Authentication (Windows) | Partial | WEL (depends on forwarded channels) |
| Authentication (Linux) | Partial | SSH_LOGIN |
| Driver loading | Good | DRIVER_CHANGE |
| User activity | Partial | USER_OBSERVED |

## Known Gaps

### High-Impact Gaps (cover many techniques)

#### Command Execution Logging
- **ATT&CK component:** Command Execution
- **Gap:** LC captures process creation with command lines, but not script-level execution (e.g., PowerShell ScriptBlock content, bash history in real-time)
- **Remediation:** Enable PowerShell ScriptBlock Logging (Group Policy) and forward Event ID 4104 via WEL adapter
- **Impact:** ~20+ techniques benefit from script content visibility

#### WMI Activity
- **ATT&CK component:** WMI Creation
- **Gap:** No native WMI event monitoring
- **Remediation:** Enable Sysmon WMI events (Event IDs 19, 20, 21) and forward via WEL
- **Impact:** T1047 (WMI), T1546.003 (WMI Event Subscription)

#### Scheduled Task/Job Details
- **ATT&CK component:** Scheduled Job Creation
- **Gap:** WEL can capture Event ID 4698, but requires explicit configuration
- **Remediation:** Forward Security Event Log with Task Scheduler audit enabled
- **Impact:** T1053 and sub-techniques

### Medium-Impact Gaps

#### Active Directory Operations
- **ATT&CK components:** AD Object Access, AD Object Modification
- **Gap:** Requires domain controller event forwarding
- **Remediation:** Forward DC Security Event Log (4661, 4662, 4670) via WEL adapter or cloud sensor
- **Impact:** T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups), many lateral movement techniques

#### Network Share Access
- **ATT&CK component:** Network Share Access
- **Gap:** Not natively captured
- **Remediation:** Forward Windows Security Event Log (5140, 5145)
- **Impact:** T1021.002 (SMB/Windows Admin Shares), T1135 (Network Share Discovery)

#### Firewall Configuration
- **ATT&CK components:** Firewall Enumeration, Firewall Disable, Firewall Rule Modification
- **Gap:** No native firewall monitoring (can detect netsh/iptables via process creation)
- **Remediation:** Forward Windows Firewall log via WEL; monitor iptables changes via auditd
- **Impact:** T1562.004 (Disable or Modify System Firewall)

### Low-Impact / Non-Endpoint Gaps

These require telemetry LC doesn't natively provide from endpoint agents:

| Component | Source Needed | LC Integration Path |
|-----------|--------------|-------------------|
| Cloud Storage Access | AWS CloudTrail, GCP Audit, Azure Activity | Cloud sensor adapters |
| Instance/VM Operations | Cloud provider audit logs | Cloud sensor adapters |
| Container/Pod Operations | Docker daemon, K8s audit logs | Syslog/webhook adapter |
| Email Collection | Mail server logs | External adapter |
| Firmware Modification | Specialized firmware monitoring | Not typically coverable |
| DNS Server Logs | DNS server query logs | Syslog adapter from DNS servers |
| Web Application Logs | Web server/WAF logs | Syslog or file adapter |
| Certificate Operations | CA audit logs | Syslog adapter |

## Recommended Remediation Priority

Based on the number of uncovered techniques each data source would address:

1. **PowerShell ScriptBlock Logging** — Enable via GPO, forward Event ID 4104 through WEL
2. **Sysmon deployment** — Provides WMI events, advanced process tracking, named pipe monitoring
3. **Windows Security Event Log forwarding** — Capture authentication (4624/4625), scheduled tasks (4698), AD operations
4. **Linux auditd** — Capture syscalls for file access, process execution, module loading
5. **Cloud audit log adapters** — AWS CloudTrail, GCP Audit Logs, Azure Activity Logs
6. **DNS server logging** — Forward DNS query logs for visibility beyond client-side DNS

## Change Log

| Date | Change | Author |
|------|--------|--------|
| 2026-03-04 | Initial gap analysis | attack-coverage-generator |
