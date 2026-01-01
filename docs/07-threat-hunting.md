# 🔍 Phase 7: Threat Hunting

This guide walks you through proactive threat hunting techniques using KQL.

**⏱️ Estimated Time:** 1 hour

---

## Overview

Threat hunting is the proactive search for threats that have evaded existing security controls. Unlike detection rules that alert on known patterns, hunting discovers:

- 🔎 Unknown threats and zero-days
- 🕵️ Advanced persistent threats (APTs)
- 📊 Anomalous behavior patterns
- 🎯 Indicators of compromise (IOCs)

### Detection vs. Hunting:

| Detection Rules | Threat Hunting |
|-----------------|----------------|
| Automated | Manual/Semi-automated |
| Known patterns | Unknown patterns |
| React to alerts | Proactive search |
| High confidence | Exploratory |

---

## Step 1: Navigate to Hunting

1. In Azure Portal, go to **Microsoft Sentinel**
2. Select your workspace: `SOC-Lab-Workspace`
3. In the left menu, click **"Hunting"**

---

## Step 2: Understand the Hunting Interface

### Hunting Dashboard:

| Section | Purpose |
|---------|---------|
| **Queries** | Pre-built and custom hunting queries |
| **Bookmarks** | Save interesting findings |
| **Livestream** | Real-time query execution |
| **Results** | Query output |

### Query Metrics:

| Metric | Meaning |
|--------|---------|
| Results Count | Total matches |
| Last Updated | When query last ran |
| MITRE ATT&CK | Mapped tactics |

---

## Hunting Query 1: Unusual Login Times

Find logins outside normal business hours.

### Create the Query:

1. Click **"+ New Query"**
2. Fill in:

**Name:** `Unusual Login Times`

**Description:** `Detects successful logins outside normal business hours (6AM-10PM) which may indicate unauthorized access.`

**Query:**
```kql
// Unusual Login Times
// Successful logins outside business hours (6AM-10PM)
let BusinessHoursStart = 6;
let BusinessHoursEnd = 22;

SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where LogonType in (2, 10)  // Interactive or RDP
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay < BusinessHoursStart or HourOfDay >= BusinessHoursEnd
| extend DayOfWeek = dayofweek(TimeGenerated)
| where DayOfWeek != 0d and DayOfWeek != 6d  // Exclude weekends (already suspicious)
| summarize 
    LoginCount = count(),
    Accounts = make_set(TargetUserName),
    IPs = make_set(IpAddress),
    FirstLogin = min(TimeGenerated),
    LastLogin = max(TimeGenerated)
    by Computer, HourOfDay
| order by LoginCount desc
```

**MITRE ATT&CK:**
- Tactic: Initial Access
- Technique: T1078 - Valid Accounts

3. Click **"Create"**

---

## Hunting Query 2: Rare Processes

Find processes that have rarely been seen on the system.

**Name:** `Rare Process Execution`

**Description:** `Identifies processes that have only run a few times, which may indicate malware or unauthorized tools.`

**Query:**
```kql
// Rare Process Execution
// Find processes that have run 5 or fewer times in the past 7 days
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688  // Process creation
| where NewProcessName !has ":\\Windows\\System32\\"  // Exclude system processes
| where NewProcessName !has ":\\Windows\\SysWOW64\\"
| where NewProcessName !has ":\\Program Files\\"
| summarize 
    ExecutionCount = count(),
    Accounts = make_set(Account),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    CommandLines = make_set(CommandLine, 5)
    by NewProcessName, Computer
| where ExecutionCount <= 5
| order by ExecutionCount asc
```

---

## Hunting Query 3: Lateral Movement Detection

Find potential lateral movement using remote execution.

**Name:** `Lateral Movement Indicators`

**Description:** `Detects patterns consistent with lateral movement such as remote service creation or remote execution.`

**Query:**
```kql
// Lateral Movement Detection
// Look for remote logon (Type 3) followed by privilege use
let RemoteLogons = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 3  // Network logon
| project 
    LogonTime = TimeGenerated,
    Computer,
    Account = TargetUserName,
    SourceIP = IpAddress;

let PrivilegeUse = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4672  // Special privileges assigned
| project 
    PrivTime = TimeGenerated,
    Computer,
    Account = TargetUserName;

RemoteLogons
| join kind=inner PrivilegeUse on Computer, Account
| where PrivTime between (LogonTime .. (LogonTime + 5m))
| summarize 
    Events = count(),
    SourceIPs = make_set(SourceIP),
    FirstSeen = min(LogonTime),
    LastSeen = max(LogonTime)
    by Computer, Account
| where Events >= 2
| order by Events desc
```

---

## Hunting Query 4: Data Exfiltration Indicators

Find unusual outbound data patterns.

**Name:** `Potential Data Exfiltration`

**Description:** `Identifies hosts with unusual outbound connection patterns that may indicate data theft.`

**Query:**
```kql
// Potential Data Exfiltration
// Large outbound connections or connections to rare destinations
// Note: Requires network flow data (NSG Flow Logs or Azure Firewall)
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where FlowDirection_s == "O"  // Outbound
| where not(DestIP_s startswith "10." or DestIP_s startswith "192.168.")
| summarize 
    TotalBytes = sum(BytesSentToDestination_d),
    ConnectionCount = count(),
    DestinationIPs = dcount(DestIP_s)
    by SrcIP_s, DestIP_s, DestPort_d
| where TotalBytes > 104857600  // More than 100MB
| order by TotalBytes desc
```

---

## Hunting Query 5: Suspicious PowerShell

Find PowerShell with suspicious characteristics.

**Name:** `Suspicious PowerShell Activity`

**Description:** `Detects PowerShell execution with characteristics commonly seen in attacks.`

**Query:**
```kql
// Suspicious PowerShell Activity
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where NewProcessName has "powershell"
| extend 
    HasEncodedCommand = CommandLine has_any ("-enc", "-EncodedCommand"),
    HasBypass = CommandLine has_any ("-ep bypass", "-ExecutionPolicy bypass"),
    HasHidden = CommandLine has_any ("-w hidden", "-WindowStyle hidden"),
    HasDownload = CommandLine has_any ("downloadstring", "downloadfile", "Net.WebClient", "Invoke-WebRequest"),
    HasInvoke = CommandLine has_any ("IEX", "Invoke-Expression", "Invoke-Command")
| extend RiskScore = toint(HasEncodedCommand) + toint(HasBypass) + toint(HasHidden) + toint(HasDownload) + toint(HasInvoke)
| where RiskScore >= 2
| project 
    TimeGenerated,
    Computer,
    Account,
    CommandLine,
    RiskScore,
    HasEncodedCommand,
    HasBypass,
    HasHidden,
    HasDownload,
    HasInvoke
| order by RiskScore desc
```

---

## Hunting Query 6: Failed Login Patterns

Analyze failed login patterns beyond simple thresholds.

**Name:** `Advanced Failed Login Analysis`

**Description:** `Analyzes failed login patterns to identify sophisticated brute force or credential stuffing attacks.`

**Query:**
```kql
// Advanced Failed Login Analysis
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize 
    TotalAttempts = count(),
    UniqueAccounts = dcount(TargetUserName),
    UniqueIPs = dcount(IpAddress),
    AccountList = make_set(TargetUserName, 10),
    IPList = make_set(IpAddress, 10),
    TimeSpan = max(TimeGenerated) - min(TimeGenerated)
    by bin(TimeGenerated, 1h)
| extend 
    AttemptsPerAccount = TotalAttempts / max(UniqueAccounts, 1),
    AttemptsPerIP = TotalAttempts / max(UniqueIPs, 1)
| extend AttackType = case(
    UniqueAccounts > 10 and UniqueIPs == 1, "Password Spray",
    UniqueAccounts == 1 and TotalAttempts > 20, "Brute Force",
    UniqueAccounts > 5 and UniqueIPs > 5, "Distributed Attack",
    "Unknown"
)
| where AttackType != "Unknown"
| order by TotalAttempts desc
```

---

## Step 3: Using Bookmarks

When you find interesting results, save them as bookmarks.

### Create a Bookmark:

1. Run a hunting query
2. Select interesting rows in results
3. Click **"Add bookmark"**
4. Fill in:

| Field | Value |
|-------|-------|
| **Name** | Descriptive name |
| **Tags** | Classification tags |
| **Notes** | Your observations |

5. Click **"Create"**

### Use Bookmarks:

- Create incidents from bookmarks
- Track investigation progress
- Share findings with team
- Build timeline of attack

---

## Step 4: Livestream Hunting

Monitor queries in real-time.

### Start Livestream:

1. In Hunting, click **"Livestream"**
2. Click **"+ Add"**
3. Enter your query
4. Set refresh interval (e.g., 30 seconds)
5. Click **"Run"**

### Use Cases:

- Monitor active attacks
- Watch for specific IOCs
- Real-time investigation
- Incident response

---

## Step 5: Hunting Methodology

### The Hunting Process:

```
1. HYPOTHESIS
   └─▶ What am I looking for?
   └─▶ What would an attacker do?

2. DATA COLLECTION
   └─▶ What logs do I have?
   └─▶ What time period?

3. INVESTIGATION
   └─▶ Run queries
   └─▶ Analyze results
   └─▶ Pivot on findings

4. DOCUMENTATION
   └─▶ Bookmark findings
   └─▶ Create incidents
   └─▶ Update detection rules

5. IMPROVEMENT
   └─▶ Convert hunts to rules
   └─▶ Close detection gaps
```

### Hunting Questions:

| Question | Hunt Type |
|----------|-----------|
| Who accessed sensitive systems at night? | Time-based |
| What new processes appeared this week? | Baseline deviation |
| Are there logins from unusual locations? | Geographic anomaly |
| What PowerShell commands were executed? | Execution analysis |
| Were any credentials reused across systems? | Credential analysis |

---

## Step 6: Converting Hunts to Detection Rules

When a hunt finds valid threats, convert it to a detection rule.

### Process:

1. Refine the query for fewer false positives
2. Go to **Analytics** → **+ Create**
3. Paste your hunting query
4. Configure scheduling and thresholds
5. Enable the rule

### Example: Hunt to Rule

**Original Hunt Query:**
```kql
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress
| where count_ > 10
```

**Refined Detection Rule:**
```kql
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4625
| where IpAddress !in ("known_safe_ips")
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts >= 15
```

---

## Hunting Best Practices

| Practice | Reason |
|----------|--------|
| Start with a hypothesis | Focus your search |
| Document everything | Create audit trail |
| Use baselines | Know what's normal |
| Pivot on findings | Follow the breadcrumbs |
| Time-box hunts | Don't go down rabbit holes |
| Share findings | Team knowledge |

---

## Verification Checklist

| Item | Status |
|------|--------|
| Unusual Login Times query created | ⬜ |
| Rare Processes query created | ⬜ |
| Lateral Movement query created | ⬜ |
| Suspicious PowerShell query created | ⬜ |
| At least one hunt executed | ⬜ |
| Bookmark created from findings | ⬜ |
| Considered converting to detection rule | ⬜ |

---

## What's Next?

Learn how to manage costs and optimize your SOC lab!

➡️ **Next:** [Phase 8: Cost Management](08-cost-management.md)

---

## Quick Reference

### Hunting Query Template:

```kql
// Query Name: [Name]
// Description: [What this query finds]
// MITRE ATT&CK: [Tactic] - [Technique]
// Author: [Your name]
// Date: [Date created]

// [Your KQL query here]
```

### MITRE ATT&CK Coverage:

| Tactic | Hunts |
|--------|-------|
| Initial Access | Unusual logins, New accounts |
| Execution | PowerShell, Process creation |
| Persistence | Scheduled tasks, Registry changes |
| Privilege Escalation | Group changes, Token manipulation |
| Defense Evasion | Log clearing, Masquerading |
| Credential Access | Failed logins, Kerberos attacks |
| Discovery | Port scanning, Account enumeration |
| Lateral Movement | Remote execution, Pass-the-hash |
| Exfiltration | Large transfers, DNS tunneling |

### Save Queries Location:

```
kql-queries/
└── hunting-queries/
    ├── unusual-login-times.kql
    ├── rare-processes.kql
    ├── lateral-movement.kql
    ├── suspicious-powershell.kql
    └── data-exfiltration.kql
```

---

[← Previous: Workbooks & Dashboards](06-workbooks-dashboards.md) | [Next: Cost Management →](08-cost-management.md)
