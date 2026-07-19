# Authentication Events

> Learn how Windows authentication events are generated, what they mean, and how security analysts use them to detect brute-force attacks, credential theft, lateral movement, privilege escalation, and unauthorized access.

---

## Table of Contents

- [Introduction](#introduction)
- [What Are Authentication Events?](#what-are-authentication-events)
- [Windows Authentication Process](#windows-authentication-process)
- [Authentication Protocols](#authentication-protocols)
- [Windows Logon Types](#windows-logon-types)
- [Common Authentication Event IDs](#common-authentication-event-ids)
- [Authentication Attack Scenarios](#authentication-attack-scenarios)
- [Investigation Workflow](#investigation-workflow)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [References](#references)

---

# Introduction

Authentication is the process of verifying the identity of a user, computer, or service before granting access to system resources.

Every successful or failed authentication attempt generates Windows Security Events that provide valuable evidence during incident response, threat hunting, and forensic investigations.

Understanding these events enables security teams to answer questions such as:

- Who logged into the system?
- When did they log in?
- Was the login successful?
- From where did the login originate?
- Which authentication protocol was used?
- Was the login interactive or remote?
- Was privileged access granted?

---

# What Are Authentication Events?

Authentication Events are Windows Security Log entries generated whenever Windows validates user credentials.

These events are recorded in:

```
Windows Logs
└── Security
```

Authentication logs help detect:

- Brute-force attacks
- Password spraying
- Credential stuffing
- Pass-the-Hash attacks
- Pass-the-Ticket attacks
- Unauthorized Remote Desktop access
- Lateral movement
- Compromised accounts

---

# Windows Authentication Process

```
User Enters Credentials
        │
        ▼
Local Security Authority (LSASS)
        │
        ▼
Authentication Package
(Kerberos / NTLM)
        │
        ▼
Credentials Valid?
      ┌───────┐
      │ Yes   │
      └──┬────┘
         ▼
 Event ID 4624
         │
         ▼
 Access Granted

      ┌───────┐
      │ No    │
      └──┬────┘
         ▼
 Event ID 4625
         │
         ▼
 Access Denied
```

---

# Authentication Protocols

Windows primarily uses two authentication protocols.

| Protocol | Used When | Security |
|----------|-----------|----------|
| Kerberos | Active Directory environments | High |
| NTLM | Legacy systems and fallback authentication | Medium |

### Kerberos

Kerberos is Microsoft's preferred authentication protocol in Active Directory environments.

Features:

- Mutual authentication
- Ticket-based authentication
- Strong encryption
- Reduced password transmission

Related Event IDs

- 4768
- 4769
- 4771

---

### NTLM

NTLM is used when Kerberos cannot be used.

Common examples:

- Workgroup computers
- Legacy applications
- Local account authentication

Related Event IDs

- 4776

---

# Windows Logon Types

One of the most important fields inside Event ID 4624 and 4625 is **Logon Type**.

Understanding the logon type provides context about how access was attempted.

| Logon Type | Description | Typical Use |
|------------|-------------|-------------|
| 2 | Interactive | Keyboard login |
| 3 | Network | SMB, shared folders |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Windows services |
| 7 | Unlock | Unlock workstation |
| 8 | Network Cleartext | IIS, Basic Authentication |
| 9 | New Credentials | RunAs |
| 10 | Remote Interactive | Remote Desktop (RDP) |
| 11 | Cached Interactive | Cached domain credentials |

---

# Common Authentication Event IDs

Click on an Event ID below to view detailed documentation.

| Event ID | Description | Importance | Documentation |
|----------:|-------------|:----------:|---------------|
| **4624** | Successful Logon | ⭐⭐⭐⭐⭐ | [View](authentication/4624-successful-logon.md) |
| **4625** | Failed Logon | ⭐⭐⭐⭐⭐ | [View](authentication/4625-failed-logon.md) |
| **4634** | Logoff | ⭐⭐⭐ | [View](authentication/4634-logoff.md) |
| **4648** | Logon Using Explicit Credentials | ⭐⭐⭐⭐ | [View](authentication/4648-explicit-credentials.md) |
| **4672** | Special Privileges Assigned to New Logon | ⭐⭐⭐⭐⭐ | [View](authentication/4672-special-privileges.md) |
| **4768** | Kerberos Authentication Ticket (TGT) Requested | ⭐⭐⭐⭐ | [View](authentication/4768-kerberos-tgt.md) |
| **4769** | Kerberos Service Ticket Requested | ⭐⭐⭐⭐ | [View](authentication/4769-service-ticket.md) |
| **4771** | Kerberos Pre-Authentication Failed | ⭐⭐⭐⭐ | [View](authentication/4771-kerberos-failure.md) |
| **4776** | NTLM Authentication | ⭐⭐⭐⭐ | [View](authentication/4776-ntlm-authentication.md) |

---

# Why Authentication Logs Matter

Authentication events are often the first indicators of malicious activity.

Examples include:

| Attack | Primary Event IDs |
|---------|------------------|
| Brute Force | 4625 |
| Password Spraying | 4625 |
| Successful Compromise | 4624 |
| Privilege Escalation | 4672 |
| Lateral Movement | 4624 + 4769 |
| Pass-the-Hash | 4624 + 4776 |
| RDP Login | 4624 (Logon Type 10) |

---

# Authentication Attack Scenarios

## Scenario 1 — Brute Force

```
4625
4625
4625
4625
4625
4625
  │
  ▼
4624
```

Possible indication:

- Password guessing
- Successful compromise after repeated failures

---

## Scenario 2 — Password Spraying

```
User A → 4625

User B → 4625

User C → 4625

User D → 4625
```

Characteristics:

- Same source IP
- Multiple usernames
- Few attempts per account

---

## Scenario 3 — Remote Desktop Attack

```
4624

Logon Type 10

↓

4672
```

Questions to ask:

- Was the source IP expected?
- Is this normal administrator activity?
- Did a suspicious process launch afterward?

---

# Investigation Workflow

When investigating suspicious authentication activity:

1. Identify the affected account.
2. Determine whether the login succeeded or failed.
3. Review the Logon Type.
4. Check the source IP address.
5. Identify the authentication protocol (Kerberos or NTLM).
6. Look for privilege assignment (4672).
7. Correlate with process creation (4688).
8. Check PowerShell activity (4104).
9. Review network connections.
10. Build a complete timeline.

---

# MITRE ATT&CK Mapping

| Event ID | ATT&CK Technique |
|-----------|------------------|
| 4625 | T1110 – Brute Force |
| 4624 | T1078 – Valid Accounts |
| 4768 | T1558 – Steal or Forge Kerberos Tickets |
| 4769 | T1550 – Use Alternate Authentication Material |
| 4776 | T1550 – Pass the Hash |

---

# What's Next?

The following pages provide detailed analysis of each authentication Event ID.

- Event ID 4624 – Successful Logon
- Event ID 4625 – Failed Logon
- Event ID 4634 – Logoff
- Event ID 4647 – User Logoff
- Event ID 4648 – Explicit Credentials
- Event ID 4672 – Special Privileges
- Event ID 4768 – Kerberos TGT
- Event ID 4769 – Service Ticket
- Event ID 4771 – Kerberos Failure
- Event ID 4776 – NTLM Authentication

Each Event ID includes:

- Description
- Event fields
- Detection guidance
- Investigation workflow
- MITRE ATT&CK mapping
- SIEM query examples
- Related events

---

# References

- Microsoft Windows Security Auditing Documentation
- Microsoft Learn
- MITRE ATT&CK Framework
- Sigma Project
- Ultimate Windows Security
