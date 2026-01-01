# 📊 Phase 6: Workbooks & Dashboards

This guide walks you through creating visual dashboards to monitor your security environment.

**⏱️ Estimated Time:** 45 minutes

---

## Overview

Workbooks are interactive dashboards in Azure Sentinel that visualize security data. They help you:

- 📈 Track security metrics at a glance
- 🗺️ Visualize attack origins on a world map
- 📉 Identify trends and patterns
- 📋 Report to stakeholders

---

## Step 1: Navigate to Workbooks

1. In Azure Portal, go to **Microsoft Sentinel**
2. Select your workspace: `SOC-Lab-Workspace`
3. In the left menu, click **"Workbooks"**
4. You'll see built-in templates and any saved workbooks

---

## Step 2: Explore Built-in Workbooks

Azure Sentinel includes many pre-built workbooks.

### Install Security Events Workbook:

1. Go to **Content hub**
2. Search for **"Windows Security Events"**
3. Click **"Install"** (if not already installed)
4. Go back to **Workbooks**
5. Click **"Templates"** tab
6. Search for **"Security Events"**
7. Click **"View template"**

### Useful Built-in Workbooks:

| Workbook | Purpose |
|----------|---------|
| Security Events | Windows event analysis |
| Azure Activity | Resource operations |
| Identity & Access | Sign-in analytics |
| Threat Intelligence | IOC tracking |
| Investigation Insights | Incident analysis |

---

## Step 3: Create Custom Security Overview Workbook

Let's create a dashboard tailored to our honeypot!

### Create New Workbook:

1. Click **"+ Add workbook"**
2. Click **"Edit"** (pencil icon)

### Add Title:

1. Click **"Add"** → **"Add text"**
2. Enter:

```markdown
# 🛡️ SOC Security Dashboard

**Last Updated:** {TimeRange:label}

---
```

3. Click **"Done Editing"**

### Add Time Range Parameter:

1. Click **"Add"** → **"Add parameters"**
2. Click **"Add Parameter"**
3. Configure:

| Field | Value |
|-------|-------|
| **Parameter name** | TimeRange |
| **Display name** | Time Range |
| **Parameter type** | Time range picker |
| **Required** | Yes |
| **Default value** | Last 24 hours |

4. Click **"Save"**
5. Click **"Done Editing"**

### Add Failed Logins Metric:

1. Click **"Add"** → **"Add metric"**
2. Configure:

**Query:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| summarize FailedLogins = count()
```

| Field | Value |
|-------|-------|
| **Title** | Failed Login Attempts |
| **Visualization** | Tiles |
| **Size** | Small |

3. Click **"Run Query"** to test
4. Click **"Done Editing"**

### Add Successful Logins Metric:

1. Click **"Add"** → **"Add metric"**
2. **Query:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4624
| where LogonType == 10
| summarize SuccessfulLogins = count()
```

### Add Unique Attackers Metric:

```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| summarize UniqueIPs = dcount(IpAddress)
```

### Add Attack Timeline Chart:

1. Click **"Add"** → **"Add query"**
2. Configure:

**Query:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID in (4624, 4625)
| summarize 
    SuccessfulLogins = countif(EventID == 4624),
    FailedLogins = countif(EventID == 4625)
    by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

| Field | Value |
|-------|-------|
| **Title** | Login Attempts Over Time |
| **Visualization** | Area chart |
| **Size** | Medium |

3. Click **"Run Query"**
4. Click **"Done Editing"**

---

## Step 4: Add Attack World Map

Visualize where attacks originate geographically.

### Add Map Visualization:

1. Click **"Add"** → **"Add query"**
2. Configure:

**Query:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| where IpAddress != "-"
| where IpAddress !startswith "10." and IpAddress !startswith "192.168."
| summarize AttackCount = count() by IpAddress
| top 100 by AttackCount
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend 
    Country = tostring(GeoInfo.country),
    City = tostring(GeoInfo.city),
    Latitude = toreal(GeoInfo.latitude),
    Longitude = toreal(GeoInfo.longitude)
| project 
    IpAddress,
    AttackCount,
    Country,
    City,
    Latitude,
    Longitude
```

| Field | Value |
|-------|-------|
| **Title** | Attack Origins World Map |
| **Visualization** | Map |
| **Size** | Large |

**Map Settings:**
- Location by: Latitude/Longitude
- Size by: AttackCount
- Color: Red gradient

3. Click **"Run Query"**
4. Click **"Done Editing"**

---

## Step 5: Add Top Attackers Table

1. Click **"Add"** → **"Add query"**
2. Configure:

**Query:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| where IpAddress != "-"
| summarize 
    FailedAttempts = count(),
    TargetAccounts = dcount(TargetUserName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IpAddress
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(GeoInfo.country)
| top 20 by FailedAttempts
| project 
    IpAddress,
    Country,
    FailedAttempts,
    TargetAccounts,
    FirstSeen,
    LastSeen,
    AttackDuration = LastSeen - FirstSeen
```

| Field | Value |
|-------|-------|
| **Title** | Top 20 Attacking IPs |
| **Visualization** | Grid |
| **Size** | Medium |

---

## Step 6: Add Account Targeting Analysis

1. Click **"Add"** → **"Add query"**

**Query:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| summarize AttackCount = count() by TargetUserName
| top 10 by AttackCount
| order by AttackCount desc
```

| Field | Value |
|-------|-------|
| **Title** | Most Targeted Accounts |
| **Visualization** | Bar chart |
| **Size** | Small |

---

## Step 7: Add Incident Summary

1. Click **"Add"** → **"Add query"**

**Query:**
```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| summarize 
    Total = count(),
    High = countif(Severity == "High"),
    Medium = countif(Severity == "Medium"),
    Low = countif(Severity == "Low"),
    Open = countif(Status == "New" or Status == "Active"),
    Closed = countif(Status == "Closed")
```

| Field | Value |
|-------|-------|
| **Title** | Incident Summary |
| **Visualization** | Tiles |

---

## Step 8: Save the Workbook

1. Click **"Done Editing"** (main toolbar)
2. Click **"Save As"**
3. Fill in:

| Field | Value |
|-------|-------|
| **Title** | SOC Security Dashboard |
| **Subscription** | Your subscription |
| **Resource group** | `SOC-Lab-RG` |
| **Location** | Same as workspace |

4. Click **"Save"**

---

## Step 9: Create RDP Monitoring Workbook

Create a dedicated workbook for RDP monitoring.

### Queries to Include:

**Hourly RDP Attempts:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID in (4624, 4625)
| where LogonType == 10
| summarize 
    Success = countif(EventID == 4624),
    Failed = countif(EventID == 4625)
    by bin(TimeGenerated, 1h)
```

**RDP Success After Failures:**
```kql
let FailedLogins = SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedCount = count() by IpAddress;

SecurityEvent
| where EventID == 4624
| where LogonType == 10
| join kind=inner FailedLogins on IpAddress
| where FailedCount > 5
| project TimeGenerated, IpAddress, Account = TargetUserName, FailedCount
```

**Attack Sources by Country:**
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(GeoInfo.country)
| summarize Attacks = count() by Country
| top 10 by Attacks
```

---

## Step 10: Share Workbooks

### Export for Version Control:

1. Open your workbook
2. Click **"Edit"**
3. Click **"</>"** (Advanced Editor)
4. Copy the JSON template
5. Save to `workbooks/security-dashboard.json`

### Share with Team:

1. Go to **Workbooks**
2. Click on your saved workbook
3. Click **"Share"**
4. Configure access permissions

---

## Best Practices

### Dashboard Design:

| Practice | Reason |
|----------|--------|
| Keep it simple | Easy to read at a glance |
| Use consistent colors | Red = bad, Green = good |
| Include time range | Context for data |
| Add drill-down links | Enable investigation |
| Refresh regularly | Current data |

### Query Optimization:

```kql
// ❌ Slow - processes all columns
SecurityEvent
| summarize count()

// ✅ Fast - filters first
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize count()
```

---

## Sample Dashboard Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│  🛡️ SOC Security Dashboard                        [Time Range: 24h] │
├────────────────┬────────────────┬────────────────┬───────────────────┤
│  FAILED LOGINS │  SUCCESS LOGINS │  UNIQUE IPS   │  INCIDENTS (NEW)  │
│     1,234      │       42        │      89       │        5          │
├────────────────┴────────────────┴────────────────┴───────────────────┤
│                                                                       │
│  [════════════ Login Attempts Over Time (Area Chart) ══════════════] │
│                                                                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  [═══════════════════ Attack World Map ════════════════════════════] │
│                                                                       │
├───────────────────────────────────┬──────────────────────────────────┤
│    Top 10 Attacking IPs           │    Most Targeted Accounts        │
│    ┌────────────────────────┐     │    ┌─────────────────────────┐   │
│    │ 185.156.73.xx  | 1,203 │     │    │ admin         ████████  │   │
│    │ 141.98.10.xx   |   892 │     │    │ administrator ██████    │   │
│    │ 45.155.205.xx  |   654 │     │    │ user          ████      │   │
│    └────────────────────────┘     │    └─────────────────────────┘   │
└───────────────────────────────────┴──────────────────────────────────┘
```

---

## Verification Checklist

| Item | Status |
|------|--------|
| SOC Security Dashboard created | ⬜ |
| Time range parameter working | ⬜ |
| Failed/Success metrics visible | ⬜ |
| Attack timeline chart showing data | ⬜ |
| World map visualization working | ⬜ |
| Top attackers table populated | ⬜ |
| Workbook saved and accessible | ⬜ |

---

## What's Next?

Now let's learn proactive threat hunting techniques!

➡️ **Next:** [Phase 7: Threat Hunting](07-threat-hunting.md)

---

## Quick Reference

### Visualization Types:

| Type | Best For |
|------|----------|
| Tiles | Single metrics |
| Grid | Detailed data |
| Bar chart | Comparisons |
| Line chart | Trends over time |
| Pie chart | Distribution |
| Map | Geographic data |
| Area chart | Volume over time |

### Color Conventions:

| Color | Meaning |
|-------|---------|
| 🔴 Red | Critical/High severity |
| 🟠 Orange | Medium severity |
| 🟡 Yellow | Low/Warning |
| 🟢 Green | Good/Success |
| 🔵 Blue | Informational |

### Export JSON Location:

Save workbook templates to:
```
workbooks/
├── security-dashboard.json
├── rdp-monitoring.json
└── incident-metrics.json
```

---

[← Previous: Automation Playbooks](05-automation-playbooks.md) | [Next: Threat Hunting →](07-threat-hunting.md)
