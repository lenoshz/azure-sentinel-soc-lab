# 🎯 Phase 4: Create Detection Rules

This guide walks you through creating custom analytics rules to detect attacks.

**⏱️ Estimated Time:** 1 hour

---

## Overview

Analytics rules are the heart of Azure Sentinel's detection capabilities. They use KQL (Kusto Query Language) to find patterns in your logs that indicate malicious activity.

### Types of Rules:

| Type | Description | Use Case |
|------|-------------|----------|
| **Scheduled** | Runs on a schedule | Most common |
| **NRT (Near Real-Time)** | Runs every minute | Critical alerts |
| **Fusion** | ML-based correlation | Advanced threats |
| **Microsoft Security** | From other MS products | Defender alerts |

---

## Step 1: Navigate to Analytics

1. In Azure Portal, go to **Microsoft Sentinel**
2. Select your workspace: `SOC-Lab-Workspace`
3. In the left menu, click **"Analytics"**
4. Click **"+ Create"** → **"Scheduled query rule"**

---

## Rule 1: RDP Brute Force Detection

This is our primary detection rule for the honeypot.

### Create the Rule:

**General Tab:**

| Field | Value |
|-------|-------|
| **Name** | `RDP Brute Force Attack Detected` |
| **Description** | `Detects multiple failed RDP login attempts from a single IP address, indicating a brute force attack.` |
| **Severity** | High |
| **MITRE ATT&CK** | Credential Access → Brute Force (T1110) |
| **Status** | Enabled |

**Set Rule Logic Tab:**

```kql
// RDP Brute Force Detection
// Detects 10+ failed RDP logins from same IP in 5 minutes
SecurityEvent
| where EventID == 4625
| where LogonType == 10  // RDP (RemoteInteractive)
| where TimeGenerated > ago(5m)
| summarize 
    FailedAttempts = count(),
    TargetAccounts = make_set(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
| where FailedAttempts >= 10
| extend 
    AttackDuration = LastAttempt - FirstAttempt,
    AccountsTargeted = array_length(TargetAccounts)
| project 
    TimeGenerated = LastAttempt,
    IpAddress,
    Computer,
    FailedAttempts,
    TargetAccounts,
    AccountsTargeted,
    AttackDuration
```

**Query Scheduling:**

| Field | Value |
|-------|-------|
| Run query every | 5 minutes |
| Lookup data from the last | 5 minutes |

**Alert Threshold:**

| Field | Value |
|-------|-------|
| Generate alert when number of query results | Is greater than 0 |

**Entity Mapping:**

| Entity Type | Identifier | Column |
|-------------|------------|--------|
| IP | Address | IpAddress |
| Host | HostName | Computer |

**Incident Settings Tab:**

- ✅ Create incidents from alerts triggered by this rule
- Group related alerts into incidents: **Enabled**
- Group alerts by: **IP Address**

**Automated Response Tab:**

(We'll configure this in Phase 5)

Click **"Review + create"** → **"Create"**

---

## Rule 2: Password Spray Detection

Detects multiple accounts targeted with same password pattern.

### Create the Rule:

**General Tab:**

| Field | Value |
|-------|-------|
| **Name** | `Password Spray Attack Detected` |
| **Description** | `Detects password spray attacks where multiple accounts are targeted with potentially the same password.` |
| **Severity** | High |
| **MITRE ATT&CK** | Credential Access → Password Spraying (T1110.003) |

**Rule Logic:**

```kql
// Password Spray Detection
// Multiple accounts from same IP with failures in short time
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(10m)
| summarize 
    UniqueAccounts = dcount(TargetUserName),
    TotalAttempts = count(),
    Accounts = make_set(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
| where UniqueAccounts >= 5  // 5+ different accounts
| where TotalAttempts >= 10  // At least 10 attempts
| extend AttackDuration = LastAttempt - FirstAttempt
| project 
    TimeGenerated = LastAttempt,
    IpAddress,
    Computer,
    UniqueAccounts,
    TotalAttempts,
    Accounts,
    AttackDuration
```

**Query Scheduling:**

| Field | Value |
|-------|-------|
| Run query every | 10 minutes |
| Lookup data from the last | 10 minutes |

---

## Rule 3: Successful Login After Brute Force

Detects when an attacker successfully logs in after multiple failures.

**General Tab:**

| Field | Value |
|-------|-------|
| **Name** | `Successful Login After Multiple Failures` |
| **Description** | `Detects successful login following multiple failed attempts - potential brute force success.` |
| **Severity** | Critical |
| **MITRE ATT&CK** | Initial Access → Valid Accounts (T1078) |

**Rule Logic:**

```kql
// Successful Login After Brute Force
let FailedLogins = SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize 
    FailedCount = count(),
    FailedAccounts = make_set(TargetUserName)
    by IpAddress;

SecurityEvent
| where EventID == 4624
| where LogonType in (10, 3)  // RDP or Network
| where TimeGenerated > ago(15m)
| join kind=inner FailedLogins on IpAddress
| where FailedCount >= 5
| project 
    TimeGenerated,
    IpAddress,
    SuccessfulAccount = TargetUserName,
    Computer,
    FailedCount,
    FailedAccounts,
    LogonType
```

---

## Rule 4: Privilege Escalation

Detects when users are added to sensitive groups.

**General Tab:**

| Field | Value |
|-------|-------|
| **Name** | `Sensitive Group Membership Change` |
| **Description** | `Detects when a user is added to a sensitive administrator group.` |
| **Severity** | High |
| **MITRE ATT&CK** | Privilege Escalation → Domain Policy Modification (T1484) |

**Rule Logic:**

```kql
// Privilege Escalation - Sensitive Group Changes
SecurityEvent
| where EventID == 4732  // User added to group
| where TimeGenerated > ago(1h)
| where TargetUserName has_any ("admin", "Admin", "Administrators", "Domain Admins", "Enterprise Admins")
| project 
    TimeGenerated,
    Computer,
    AddedUser = MemberName,
    TargetGroup = TargetUserName,
    AddedBy = SubjectUserName,
    SubjectDomainName
```

---

## Rule 5: Suspicious PowerShell Execution

Detects potentially malicious PowerShell commands.

**General Tab:**

| Field | Value |
|-------|-------|
| **Name** | `Suspicious PowerShell Execution` |
| **Description** | `Detects PowerShell commands with potentially malicious patterns.` |
| **Severity** | Medium |
| **MITRE ATT&CK** | Execution → PowerShell (T1059.001) |

**Rule Logic:**

```kql
// Suspicious PowerShell Detection
SecurityEvent
| where EventID == 4688  // Process creation
| where TimeGenerated > ago(1h)
| where NewProcessName has "powershell"
| where CommandLine has_any (
    "-enc", "-EncodedCommand",
    "bypass", "-ep bypass",
    "IEX", "Invoke-Expression",
    "downloadstring", "downloadfile",
    "Net.WebClient", "Invoke-WebRequest",
    "hidden", "-w hidden"
)
| project 
    TimeGenerated,
    Computer,
    Account,
    ParentProcess = ParentProcessName,
    ProcessName = NewProcessName,
    CommandLine
```

---

## Rule 6: Account Lockout Detection

Detects account lockouts which may indicate brute force.

**General Tab:**

| Field | Value |
|-------|-------|
| **Name** | `Account Lockout Detected` |
| **Description** | `Detects when accounts are locked out due to failed login attempts.` |
| **Severity** | Medium |
| **MITRE ATT&CK** | Credential Access → Brute Force (T1110) |

**Rule Logic:**

```kql
// Account Lockout Detection
SecurityEvent
| where EventID == 4740  // Account lockout
| where TimeGenerated > ago(1h)
| project 
    TimeGenerated,
    Computer,
    LockedAccount = TargetUserName,
    TargetDomainName,
    CallerComputerName = Computer
```

---

## Importing Pre-Built Rules

Azure Sentinel includes many pre-built detection rules.

### Enable Community Rules:

1. Go to **Content hub** (left menu)
2. Search for **"Windows Security Events"**
3. Click **"Install"**
4. After installation, go to **Analytics**
5. Click **"Rule templates"** tab
6. Filter by: **Source = Windows Security Events**
7. Select useful rules and click **"Create rule"**

### Recommended Built-in Rules:

| Rule | Description |
|------|-------------|
| Failed logon attempts in last 60 min | Basic brute force |
| Security Event log cleared | Anti-forensics |
| Multiple RDP connections from single IP | Suspicious activity |
| User account created | Account creation |
| User added to admin group | Privilege escalation |

---

## Testing Your Rules

### Generate Test Attacks:

1. **From another device** (not your VM), attempt to RDP with wrong passwords 15+ times
2. Wait 5-10 minutes for the rule to trigger
3. Check **Incidents** page in Sentinel

### Verify Rule Execution:

1. Go to **Analytics** → select your rule
2. Click **"Last run"** to see execution history
3. Green checkmark = rule ran successfully

### Manual Query Test:

Before creating a rule, test the query manually:

1. Go to **Logs**
2. Paste your KQL query
3. Click **"Run"**
4. Verify you see expected results

---

## Rule Performance Tips

### Optimize Queries:

```kql
// ❌ Bad - scans all data
SecurityEvent
| where Activity contains "failed"

// ✅ Good - filters first
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
```

### Best Practices:

| Practice | Reason |
|----------|--------|
| Filter by TimeGenerated first | Reduces data scanned |
| Use specific EventIDs | More efficient than string matching |
| Avoid wildcards when possible | Better performance |
| Test queries manually first | Catch errors early |
| Start with higher thresholds | Reduce false positives |

---

## Understanding Alert Fatigue

Too many alerts = analysts ignore them!

### Tuning Recommendations:

| Initial Threshold | If Too Many Alerts | If Too Few |
|-------------------|-------------------|------------|
| 10 failed logins | Increase to 15-20 | Decrease to 5 |
| 5 minute window | Increase to 10 min | Decrease to 2 min |

### Allowlisting:

If legitimate IPs trigger alerts, add exceptions:

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress !in ("10.0.0.1", "your_admin_ip")
| // rest of query
```

---

## Verification Checklist

| Item | Status |
|------|--------|
| RDP Brute Force rule created | ⬜ |
| Password Spray rule created | ⬜ |
| Successful Login After Failures rule created | ⬜ |
| Rules are enabled and running | ⬜ |
| Test attack generated incidents | ⬜ |

---

## What's Next?

Now let's automate responses to these detections!

➡️ **Next:** [Phase 5: Automation Playbooks](05-automation-playbooks.md)

---

## Quick Reference

### Rule Components:

```
┌─────────────────────────────────────────────────────┐
│              ANALYTICS RULE                          │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐     ┌─────────────┐                │
│  │   General   │────▶│ Rule Logic  │                │
│  │   Name      │     │ KQL Query   │                │
│  │   Severity  │     │ Schedule    │                │
│  └─────────────┘     └─────────────┘                │
│          │                  │                        │
│          ▼                  ▼                        │
│  ┌─────────────┐     ┌─────────────┐                │
│  │   Entity    │     │  Incident   │                │
│  │   Mapping   │     │  Settings   │                │
│  └─────────────┘     └─────────────┘                │
│          │                  │                        │
│          └──────────────────┘                        │
│                    │                                 │
│                    ▼                                 │
│          ┌─────────────────┐                        │
│          │   Automated     │                        │
│          │   Response      │                        │
│          └─────────────────┘                        │
└─────────────────────────────────────────────────────┘
```

### Common Event IDs:

| Event ID | Description | Use Case |
|----------|-------------|----------|
| 4624 | Successful login | Access tracking |
| 4625 | Failed login | Brute force detection |
| 4634 | Logoff | Session tracking |
| 4648 | Explicit credentials | Pass-the-hash |
| 4672 | Special privileges | Admin detection |
| 4688 | Process creation | Command execution |
| 4720 | Account created | Account creation |
| 4732 | User added to group | Privilege escalation |
| 4740 | Account locked | Lockout tracking |

---

[← Previous: Data Connectors](03-data-connectors.md) | [Next: Automation Playbooks →](05-automation-playbooks.md)
