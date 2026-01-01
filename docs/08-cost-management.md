# 💰 Phase 8: Cost Management

This guide helps you manage Azure costs and optimize your SOC Lab spending.

**⏱️ Estimated Time:** 30 minutes

---

## Overview

Managing costs is crucial, especially when using Azure Student credits ($100). This guide covers:

- 📊 Understanding what costs money
- ⚠️ Setting up alerts
- 💡 Optimization tips
- 🧹 Cleanup procedures

---

## Understanding Costs

### What Costs Money:

| Resource | Cost Driver | Typical Cost |
|----------|-------------|--------------|
| **Virtual Machines** | Running time | $8-10/month (B1s) |
| **Log Analytics** | Data ingestion | FREE up to 5GB/day |
| **Azure Sentinel** | Data analysis | FREE trial (31 days, 10GB/day) |
| **Storage** | GB stored | ~$0.02/GB/month |
| **Public IP** | Allocated time | ~$3/month |
| **Bandwidth** | Outbound data | FREE up to 5GB/month |

### Free Tier Limits:

| Service | Free Amount |
|---------|-------------|
| Log Analytics | 5 GB/day ingestion |
| Azure Sentinel | 10 GB/day (31 day trial) |
| Azure AD | Basic features |
| Storage | 5 GB (standard tier) |

---

## Step 1: View Current Costs

### Check Cost Analysis:

1. In Azure Portal, search for **"Cost Management"**
2. Click **"Cost Management + Billing"**
3. Click **"Cost Management"** (left menu)
4. Click **"Cost analysis"**

### View by Resource Group:

1. In Cost analysis, click **"Group by"**
2. Select **"Resource group"**
3. Filter to `SOC-Lab-RG`
4. Change timeframe to **"Month to date"**

### Understand the Breakdown:

```
SOC-Lab-RG Monthly Estimate
├── Virtual Machines    ~$8-10  (Honeypot-VM)
├── Storage            ~$1-2   (VM disks)
├── Public IP          ~$3     (Honeypot-VM-ip)
├── Networking         ~$0     (VNet, NSG)
├── Log Analytics      ~$0     (Under free tier)
└── Azure Sentinel     ~$0     (Trial period)
    ─────────────────────────
    TOTAL              ~$10-15/month
```

---

## Step 2: Set Up Budget Alerts

### Create a Budget:

1. In Cost Management, click **"Budgets"**
2. Click **"+ Add"**
3. Configure:

| Field | Value |
|-------|-------|
| **Name** | `SOC-Lab-Monthly-Budget` |
| **Reset period** | Monthly |
| **Creation date** | Today |
| **Expiration date** | 1 year from now |
| **Budget amount** | $20 |

4. Click **"Next"**

### Set Alert Conditions:

| Alert | % of Budget | Amount | Action |
|-------|-------------|--------|--------|
| Alert 1 | 50% | $10 | Email |
| Alert 2 | 75% | $15 | Email |
| Alert 3 | 90% | $18 | Email |
| Alert 4 | 100% | $20 | Email |

5. Enter your email address
6. Click **"Create"**

### Create Resource Group Budget:

For more granular control:

1. Go to your Resource Group (`SOC-Lab-RG`)
2. Click **"Budgets"** (left menu)
3. Create a $15/month budget

---

## Step 3: Enable Cost Saving Features

### VM Auto-Shutdown:

1. Go to your VM (`Honeypot-VM`)
2. Click **"Auto-shutdown"** (left menu)
3. Configure:

| Setting | Value |
|---------|-------|
| **Enabled** | Yes |
| **Shutdown time** | 7:00 PM |
| **Time zone** | Your timezone |
| **Notification** | Optional (email) |

4. Click **"Save"**

> 💡 Auto-shutdown saves ~50% on VM costs!

### Use Smallest VM Size:

If you need to resize:

1. Stop the VM (deallocate)
2. Click **"Size"**
3. Select **B1s** (cheapest option)
4. Click **"Resize"**
5. Start the VM

### Use Standard SSD (Not Premium):

1. Go to VM → **"Disks"**
2. Verify disk type is **Standard SSD** (not Premium)
3. Premium SSD costs 3-4x more!

---

## Step 4: Monitor Data Ingestion

Data ingestion is the main cost driver for Log Analytics.

### Check Current Usage:

1. Go to **Log Analytics workspace** (`SOC-Lab-Workspace`)
2. Click **"Usage and estimated costs"** (left menu)
3. View:
   - Daily cap status
   - Data volume trend
   - Estimated costs

### View Usage by Table:

Run this query in **Logs**:

```kql
Usage
| where TimeGenerated > ago(30d)
| summarize GB = sum(Quantity) / 1000 by DataType
| order by GB desc
```

### Set Daily Cap (Safety Net):

1. In Usage and estimated costs, click **"Daily Cap"**
2. Toggle to **"On"**
3. Set cap: **1 GB** (well under free tier)
4. Click **"OK"**

> ⚠️ When cap is reached, data ingestion stops until next day!

---

## Step 5: Optimize Log Collection

### Reduce Security Event Collection:

1. Go to **Microsoft Sentinel** → **Data connectors**
2. Click on **Windows Security Events**
3. Click **"Open connector page"**
4. Edit the Data Collection Rule
5. Change from "All Events" to "Common"

### Event Collection Levels:

| Level | Data Volume | Coverage |
|-------|-------------|----------|
| All | High | Everything |
| Common | Medium | Most attacks |
| Minimal | Low | Critical only |
| Custom | Varies | Your selection |

### Recommended: Common Level

Captures:
- 4624, 4625 (Logon events)
- 4648 (Explicit credentials)
- 4672 (Special privileges)
- 4720, 4726 (Account management)
- 4732, 4733 (Group changes)

---

## Step 6: Clean Up When Not In Use

### Stop VM When Not Needed:

```powershell
# Stop and deallocate (no charges)
az vm deallocate --name Honeypot-VM --resource-group SOC-Lab-RG

# Start when needed
az vm start --name Honeypot-VM --resource-group SOC-Lab-RG
```

> ⚠️ "Stop" in portal still charges! Use "Stop (deallocate)"

### Delete Resources Temporarily:

If taking a break from the lab:

1. Export important queries and workbooks
2. Delete the resource group
3. Re-create when ready

```powershell
# Delete entire resource group
az group delete --name SOC-Lab-RG --yes

# This removes ALL resources in the group!
```

---

## Step 7: Cost Monitoring Dashboard

Create a simple cost tracking system.

### Weekly Cost Check Routine:

| Day | Action |
|-----|--------|
| Monday | Check Cost Analysis dashboard |
| Wednesday | Review data ingestion rates |
| Friday | Verify VM auto-shutdown worked |

### Key Metrics to Monitor:

| Metric | Target | Alert If |
|--------|--------|----------|
| Monthly spend | < $15 | > $10 |
| Daily VM hours | < 8 hours | > 12 hours |
| Data ingestion | < 2 GB/day | > 4 GB/day |

---

## Cost Projection

### Staying Within $100 Student Credit:

| Scenario | Monthly Cost | Months of Lab |
|----------|--------------|---------------|
| **Optimized** (auto-shutdown) | ~$8-10 | 10+ months |
| **Standard** (manual shutdown) | ~$15-20 | 5-6 months |
| **Always On** (no shutdown) | ~$30-40 | 2-3 months |

### Optimization Impact:

| Optimization | Monthly Savings |
|--------------|-----------------|
| Auto-shutdown | $5-8 |
| B1s VM size | $5-10 vs B2s |
| Standard SSD | $3-5 vs Premium |
| Common events only | $0 (stay in free tier) |
| **Total Savings** | **$13-23** |

---

## Emergency: Unexpected Costs

If you see unexpected charges:

### Immediate Actions:

1. **Stop all VMs** (deallocate, not just stop)
2. **Check for orphaned resources** (public IPs, disks)
3. **Review Activity Log** for unauthorized changes
4. **Set lower daily caps**

### Find Cost Sources:

```bash
# List all resources in subscription
az resource list --output table

# Check running VMs
az vm list --show-details --query "[?powerState=='VM running']" --output table
```

### Check for Orphaned Resources:

1. Go to **Resource groups** → `SOC-Lab-RG`
2. Look for:
   - Public IPs not attached to VMs
   - Disks not attached to VMs
   - Unused storage accounts
3. Delete orphaned resources

---

## Clean Up Procedure

When you're done with the lab or need to save credits:

### Option 1: Keep Sentinel, Stop VM

1. Deallocate VM (saves ~$8/month)
2. Keep Sentinel and Log Analytics (free tier)
3. Restart VM when needed

### Option 2: Delete Everything

1. Export any important data:
   - Workbook templates
   - KQL queries
   - Playbook JSON

2. Delete resource group:
```bash
az group delete --name SOC-Lab-RG --yes --no-wait
```

3. Verify deletion:
```bash
az group list --output table
```

---

## Azure Cost Alerts Automation

### Logic App for Cost Alerts:

Create a Logic App that:
1. Triggers on budget alert
2. Sends Teams/Slack notification
3. Optionally stops VMs automatically

---

## Quick Cost Reference

### Estimated Monthly Costs:

| Configuration | Cost |
|---------------|------|
| VM B1s + auto-shutdown | ~$4-5 |
| Public IP (static) | ~$3 |
| Storage (30GB SSD) | ~$2 |
| Log Analytics (<5GB/day) | $0 |
| Sentinel (trial) | $0 |
| **TOTAL (optimized)** | **~$9-10** |

### Cost per Hour:

| Resource | $/Hour |
|----------|--------|
| B1s VM (running) | ~$0.012 |
| B2s VM (running) | ~$0.046 |
| B1s VM (deallocated) | $0 |

---

## Verification Checklist

| Item | Status |
|------|--------|
| Budget alert created | ⬜ |
| VM auto-shutdown enabled | ⬜ |
| Using B1s VM size | ⬜ |
| Daily cap set on Log Analytics | ⬜ |
| Using Common event collection | ⬜ |
| Weekly cost check scheduled | ⬜ |
| Know how to deallocate VM | ⬜ |
| Orphaned resources removed | ⬜ |

---

## Summary

Congratulations! You've completed all phases of the Azure Sentinel SOC Lab! 🎉

### What You've Built:

- ✅ Azure Sentinel SIEM environment
- ✅ Honeypot VM attracting real attacks
- ✅ Data connectors ingesting logs
- ✅ Detection rules catching attackers
- ✅ Automation playbooks responding to threats
- ✅ Dashboards visualizing security
- ✅ Threat hunting capabilities
- ✅ Cost management controls

### Next Steps:

- [ ] Add more honeypots (Linux, web apps)
- [ ] Create more detection rules
- [ ] Practice incident investigation
- [ ] Study for SC-200 certification
- [ ] Share your experience!

---

[← Back to Main README](../README.md)
