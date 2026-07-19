
[⬅️ Authentication Overview](../authentication.md) | [➡️ Next: Event ID 4625](4625-failed-logon.md)

---

# Event ID 4624 – Successful Logon

![Category](https://img.shields.io/badge/Category-Authentication-0A66C2?style=flat-square)
![Severity](https://img.shields.io/badge/Severity-Informational-3B82F6?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-T1078-CB3837?style=flat-square)

> 📖 **Reading Time:** 8 min
> **Category:** Authentication  
> **Log Source:** Windows Security Log  
> **Severity:** Informational (Can indicate malicious activity depending on context)  
> **MITRE ATT&CK:** T1078 – Valid Accounts

---

# Overview

**Event ID 4624** is generated whenever Windows successfully authenticates a user, computer account, or service account.

Although this event simply records a successful logon, it is one of the **most important Windows Security Events** for SOC analysts because nearly every attack involving stolen credentials, remote access, privilege escalation, or lateral movement begins with a successful authentication.

By itself, Event ID 4624 is usually benign. However, when correlated with other security events such as **4672 (Special Privileges Assigned)**, **4688 (Process Creation)**, or **4104 (PowerShell Script Block Logging)**, it can reveal malicious activity.

---

# Why This Event Matters

Every successful login leaves a footprint.

Security analysts use Event ID 4624 to answer questions such as:

- Who logged in?
- When did they log in?
- Was the login local or remote?
- Which computer initiated the login?
- Was Kerberos or NTLM used?
- Was the account an administrator?
- Was the login expected?

During investigations, Event ID 4624 often becomes the starting point for building an attack timeline.

---

# Event Information

| Property | Value |
|----------|-------|
| Event ID | 4624 |
| Log Name | Security |
| Category | Logon |
| Trigger | Successful authentication |
| Logged By | Windows Security Auditing |
| Default Enabled | Yes |

---

# Common Logon Types

The **Logon Type** field provides valuable context about how the user authenticated.

| Logon Type | Name | Typical Scenario | Suspicious? |
|------------|------|------------------|-------------|
| 2 | Interactive | User logs in locally using keyboard | Usually No |
| 3 | Network | SMB shares, file access, remote resources | Depends |
| 4 | Batch | Scheduled Task | Usually No |
| 5 | Service | Windows Service | Usually No |
| 7 | Unlock | User unlocks workstation | No |
| 8 | NetworkCleartext | IIS, Basic Authentication | Investigate |
| 9 | NewCredentials | RunAs | Investigate |
| 10 | RemoteInteractive | Remote Desktop (RDP) | Frequently Investigated |
| 11 | CachedInteractive | Cached Domain Credentials | Usually Normal |

> **Tip:** Logon Types **3** and **10** deserve extra attention during investigations because attackers commonly use SMB and Remote Desktop for lateral movement.

---

# Important Event Fields

| Field | Description | Why It Matters |
|--------|-------------|----------------|
| SubjectUserName | Account that initiated the logon | Identifies who requested access |
| TargetUserName | Account successfully authenticated | Primary account under investigation |
| LogonType | Authentication method | Helps identify attack vector |
| AuthenticationPackage | Kerberos or NTLM | Indicates authentication protocol |
| WorkstationName | Source computer | Useful for tracing activity |
| IpAddress | Source IP address | Critical during investigations |
| ProcessName | Process responsible for authentication | Detect unusual processes |
| LogonGuid | Correlates related events | Timeline analysis |

---

# Example Event

```text
Event ID: 4624

Account Name: Administrator

Logon Type: 10

Authentication Package: Negotiate

Source IP: 192.168.1.45

Process: winlogon.exe
```

This example shows a successful Remote Desktop login using the **Administrator** account.

---

# Understanding Logon Types

## Logon Type 2 – Interactive

A user physically signs in using the local keyboard and monitor.

Example:

- Office employee logging into a workstation.

Usually considered normal.

---

## Logon Type 3 – Network

Generated when someone accesses:

- Shared folders
- SMB
- Network printers
- Remote resources

Common during lateral movement.

---

## Logon Type 10 – Remote Interactive

Generated during:

- Remote Desktop Protocol (RDP)

Often investigated because attackers frequently use RDP after obtaining credentials.

Questions to ask:

- Was RDP expected?
- Did the login occur outside business hours?
- Is the source IP trusted?

---

# Authentication Packages

Windows records the authentication package used.

| Package | Meaning |
|----------|----------|
| Kerberos | Preferred authentication in Active Directory |
| NTLM | Legacy authentication |
| Negotiate | Automatically selects Kerberos or NTLM |

Frequent NTLM usage in modern domains may indicate legacy systems or attacker activity.

---

# Common Attack Scenarios

## Scenario 1 – Successful Brute Force

```
4625
4625
4625
4625
4625
 ↓
4624
```

Possible explanation:

Repeated failed logins followed by a successful authentication.

Investigate:

- Source IP
- Target account
- Password spray indicators

---

## Scenario 2 – Suspicious RDP Login

```
4624

Logon Type: 10

↓

4672

↓

4688
```

Potential attack chain:

- Remote Desktop login
- Administrative privileges assigned
- Suspicious process launched

---

## Scenario 3 – Pass-the-Hash

```
4776

↓

4624

↓

4688
```

Indicators:

- NTLM authentication
- Network logon
- Administrative account
- Lateral movement

---

# Investigation Checklist

When investigating Event ID 4624, verify:

- Is the account expected?
- Is the source IP trusted?
- Is the login time normal?
- Was MFA expected?
- Was the authentication Kerberos or NTLM?
- Did the user receive administrative privileges?
- Was a suspicious process started afterward?
- Were PowerShell events generated?
- Were scheduled tasks or services created?

---

# Correlate With These Event IDs

| Event ID | Reason |
|----------|--------|
| 4625 | Failed login attempts before success |
| 4634 | User logoff |
| 4648 | Explicit credentials used |
| 4672 | Special privileges assigned |
| 4688 | Process creation |
| 4697 | Service installation |
| 4698 | Scheduled task creation |
| 4104 | PowerShell execution |
| 1102 | Audit log cleared |

---

# Detection Tips

Look for:

- Administrator logins outside business hours.
- Remote Desktop logins from unfamiliar IP addresses.
- Logon Type 3 from unusual hosts.
- Multiple successful logins across several servers in a short period.
- NTLM authentication where Kerberos is expected.
- Authentication followed immediately by PowerShell or command execution.

---

# Sample Splunk Query

```spl
index=wineventlog EventCode=4624
| stats count by Account_Name, Logon_Type, host
```

---

# Sample Microsoft Sentinel (KQL)

```kusto
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer, IpAddress, LogonType
| order by TimeGenerated desc
```

---

# Sample Sigma Detection

```yaml
title: Suspicious RDP Logon
id: 9d8b9f2d-example
status: experimental

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4624
    LogonType: 10

condition: selection

level: medium
```

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |
| T1021.001 | Remote Services: RDP (when Logon Type 10 is involved) |
| T1550 | Use Alternate Authentication Material (when correlated with NTLM/Kerberos abuse) |

---

# Common False Positives

Not every successful login is suspicious.

Examples include:

- Employees starting their workday.
- Scheduled service account logins.
- Backup software authentication.
- Antivirus services.
- Domain controller replication.
- Automated administrative tasks.

Context is essential before raising an alert.

---

# Analyst Tips

- Never investigate Event ID 4624 in isolation.
- Always review the **Logon Type**.
- Correlate with **4672**, **4688**, and **4104**.
- Compare the source IP with known assets.
- Build a timeline of events before drawing conclusions.

---

# References

- Microsoft Learn – Windows Security Auditing
- Ultimate Windows Security Encyclopedia
- MITRE ATT&CK Framework
- Sigma Project
