# 🔌 Phase 3: Connect Data Sources

This guide walks you through connecting various log sources to Azure Sentinel.

**⏱️ Estimated Time:** 30 minutes

---

## Overview

Data connectors are the bridges between your log sources and Azure Sentinel. In this phase, we'll connect:

1. **Windows Security Events** - From our honeypot VM
2. **Azure Activity Logs** - Azure resource operations
3. **Azure AD Sign-in Logs** - User authentication events (optional)

---

## Step 1: Navigate to Data Connectors

1. In Azure Portal, go to **Microsoft Sentinel**
2. Select your workspace: `SOC-Lab-Workspace`
3. In the left menu, click **"Data connectors"**
4. You'll see a list of available connectors

> 💡 **Tip:** Use the search bar to quickly find connectors

---

## Step 2: Connect Windows Security Events

This is the most important connector for our honeypot!

### Install the Connector:

1. Search for **"Windows Security Events via AMA"**
2. Click on the connector
3. Click **"Open connector page"**

### Configure Data Collection Rule:

1. Click **"+ Create data collection rule"**
2. Fill in:

| Field | Value |
|-------|-------|
| **Rule Name** | `Honeypot-DCR` |
| **Subscription** | Your subscription |
| **Resource Group** | `SOC-Lab-RG` |

3. Click **"Next: Resources"**

### Add VM as Resource:

1. Expand your subscription → `SOC-Lab-RG`
2. Check the box next to `Honeypot-VM`
3. Click **"Next: Collect"**

### Select Events to Collect:

| Option | Description | Recommendation |
|--------|-------------|----------------|
| All Security Events | Everything | ❌ Too much data |
| Common | Most useful events | ✅ Recommended |
| Minimal | Critical events only | ⚠️ May miss attacks |
| Custom | Your selection | Advanced users |

4. Select **"Common"**
5. Click **"Next: Review + create"**
6. Click **"Create"**

### Verify Installation:

Wait 5-10 minutes, then verify:

1. Go to **Log Analytics workspace** → `SOC-Lab-Workspace`
2. Click **"Logs"**
3. Run this query:

```kql
SecurityEvent
| take 10
```

If you see results, the connector is working!

---

## Step 3: Connect Azure Activity Logs

This captures all Azure resource operations.

### Steps:

1. In Data connectors, search for **"Azure Activity"**
2. Click on the connector
3. Click **"Open connector page"**
4. Click **"Launch Azure Policy Assignment wizard"**
5. Fill in:

| Field | Value |
|-------|-------|
| **Scope** | Your subscription |
| **Log Analytics Workspace** | `SOC-Lab-Workspace` |

6. Click **"Review + create"**
7. Click **"Create"**

### Verify:

Wait 15-20 minutes, then run:

```kql
AzureActivity
| take 10
```

---

## Step 4: Connect Azure AD Logs (Optional)

> ⚠️ **Note:** Requires Azure AD Premium P1/P2 license

If you have Azure AD Premium:

1. Search for **"Azure Active Directory"**
2. Click **"Open connector page"**
3. Check these logs:
   - ✅ Sign-in logs
   - ✅ Audit logs
   - ✅ Non-interactive user sign-in logs
   - ✅ Service principal sign-in logs
   - ✅ Managed identity sign-in logs

4. Click **"Apply Changes"**

### Verify:

```kql
SigninLogs
| take 10
```

---

## Step 5: Enable Additional Free Connectors

These connectors are free and useful:

### Microsoft Defender for Cloud (Free Tier)

1. Search for **"Microsoft Defender for Cloud"**
2. Click **"Open connector page"**
3. Find your subscription
4. Toggle **"Status"** to **On**
5. Under "Create incidents", toggle **On**

### Azure Firewall (If using)

1. Search for **"Azure Firewall"**
2. Follow the configuration wizard
3. Select your Log Analytics workspace

---

## Step 6: Verify All Connections

Go back to the Data connectors page and verify status:

| Connector | Status | Data Tables |
|-----------|--------|-------------|
| Windows Security Events | 🟢 Connected | SecurityEvent |
| Azure Activity | 🟢 Connected | AzureActivity |
| Azure AD (if enabled) | 🟢 Connected | SigninLogs, AuditLogs |

---

## Understanding the Data

### SecurityEvent Table Schema

| Column | Description | Example |
|--------|-------------|---------|
| TimeGenerated | Event timestamp | 2024-01-15T10:30:00Z |
| EventID | Windows event ID | 4625 (failed login) |
| Computer | Source machine | Honeypot-VM |
| Account | Target account | psychonaut |
| IpAddress | Source IP | 185.156.73.xxx |
| LogonType | Type of logon | 10 (RemoteInteractive/RDP) |
| Activity | Event description | An account failed to log on |

### Key Event IDs to Monitor

| Event ID | Description | Severity |
|----------|-------------|----------|
| 4624 | Successful logon | Info |
| 4625 | Failed logon | Warning |
| 4634 | Logoff | Info |
| 4648 | Explicit credentials logon | Warning |
| 4672 | Special privileges assigned | High |
| 4720 | User account created | Medium |
| 4732 | User added to group | Medium |
| 4740 | Account locked out | High |

---

## Testing the Connection

### Generate Test Events:

1. RDP to your honeypot VM with **wrong password** (3 times)
2. RDP with **correct password**
3. Open PowerShell and run: `whoami`

### Query the Events:

Wait 5 minutes, then run:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer == "Honeypot-VM"
| summarize count() by EventID, Activity
| order by count_ desc
```

You should see:
- Event 4625 (failed logins)
- Event 4624 (successful login)
- Event 4688 (process creation - PowerShell)

---

## Data Ingestion Latency

Understanding when data appears in Sentinel:

| Data Type | Typical Latency |
|-----------|-----------------|
| Security Events | 2-5 minutes |
| Azure Activity | 5-15 minutes |
| Azure AD Logs | 2-10 minutes |
| NSG Flow Logs | 10-15 minutes |

> 💡 **Tip:** If data isn't appearing, wait up to 20 minutes before troubleshooting

---

## Cost Considerations

| Data Source | Volume/Day | Estimated Cost |
|-------------|------------|----------------|
| Windows Security Events | 100MB - 1GB | FREE (under 5GB) |
| Azure Activity | 10-50MB | FREE |
| Azure AD Logs | 50-200MB | FREE |
| **Total** | ~1-2GB | **FREE** |

> ✅ Our setup typically uses less than 2GB/day, well under the free tier!

---

## Troubleshooting

### "No data appearing in SecurityEvent"

1. Verify the Data Collection Rule was created successfully
2. Check VM has Azure Monitor Agent installed:
   - In VM, go to **Extensions + applications**
   - Look for **AzureMonitorWindowsAgent**
3. Ensure VM is running (not deallocated)
4. Wait 15-20 minutes for initial data

### "AzureActivity table is empty"

1. Policy assignments can take 15-30 minutes to apply
2. Verify the policy was assigned to correct subscription
3. Generate some activity (create/modify a resource)

### "Connector shows 'Connected' but no data"

1. Check the specific table in Logs
2. Verify time range (last 24 hours)
3. Some connectors need activity to generate logs
4. Review Data Collection Rule settings

---

## Verification Checklist

| Item | Status |
|------|--------|
| Windows Security Events connector connected | ⬜ |
| Data Collection Rule created for honeypot | ⬜ |
| SecurityEvent table has data | ⬜ |
| Azure Activity connector enabled | ⬜ |
| AzureActivity table has data | ⬜ |
| Azure AD connector configured (optional) | ⬜ |

---

## What's Next?

Now that logs are flowing, let's create detection rules to catch attackers!

➡️ **Next:** [Phase 4: Detection Rules](04-detection-rules.md)

---

## Quick Reference

### Useful KQL Queries:

```kql
// Check data ingestion by table
Usage
| where TimeGenerated > ago(24h)
| summarize TotalGB = sum(Quantity) / 1000 by DataType
| order by TotalGB desc

// Check connector health
Heartbeat
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| where LastHeartbeat < ago(15m)

// View recent security events
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize count() by EventID
| order by count_ desc
```

### Data Tables Reference:

| Connector | Primary Table | Secondary Tables |
|-----------|---------------|------------------|
| Windows Security Events | SecurityEvent | Event |
| Azure Activity | AzureActivity | AzureMetrics |
| Azure AD | SigninLogs | AuditLogs, AADNonInteractiveUserSignInLogs |

---

[← Previous: Honeypot Deployment](02-honeypot-deployment.md) | [Next: Detection Rules →](04-detection-rules.md)
