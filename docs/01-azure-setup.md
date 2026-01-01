# 📘 Phase 1: Azure Sentinel Setup

This guide walks you through setting up Azure Sentinel (Microsoft Sentinel) from scratch.

**⏱️ Estimated Time:** 30 minutes

---

## Prerequisites

Before starting, ensure you have:

- [x] Azure account with active subscription (Azure Student $100 credit works!)
- [x] Global Administrator or Security Administrator role
- [x] Web browser (Chrome/Edge recommended)

---

## Step 1: Log into Azure Portal

1. Navigate to [https://portal.azure.com](https://portal.azure.com)
2. Sign in with your Azure account credentials
3. You should see the Azure Portal dashboard

> 💡 **Tip:** Bookmark this page - you'll use it frequently!

---

## Step 2: Create a Resource Group

A Resource Group is a container that holds all your Azure resources. This makes cleanup easy later.

### Steps:

1. In the search bar at the top, type **"Resource groups"**
2. Click **"Resource groups"** from the results
3. Click **"+ Create"**
4. Fill in the details:

| Field | Value |
|-------|-------|
| **Subscription** | Your Azure subscription |
| **Resource group** | `SOC-Lab-RG` |
| **Region** | `East US` (or closest to you) |

5. Click **"Review + create"**
6. Click **"Create"**

> ✅ **Success:** You should see "Resource group created" notification

---

## Step 3: Create Log Analytics Workspace

Log Analytics Workspace is where all your logs are stored and queried.

### Steps:

1. In the search bar, type **"Log Analytics workspaces"**
2. Click **"Log Analytics workspaces"** from results
3. Click **"+ Create"**
4. Fill in the details:

| Field | Value |
|-------|-------|
| **Subscription** | Your Azure subscription |
| **Resource group** | `SOC-Lab-RG` |
| **Name** | `SOC-Lab-Workspace` |
| **Region** | `East US` (same as resource group) |

5. Click **"Review + Create"**
6. Click **"Create"**
7. Wait for deployment to complete (1-2 minutes)

> ✅ **Success:** You should see "Deployment succeeded"

---

## Step 4: Enable Microsoft Sentinel

Now we'll enable Sentinel on top of the Log Analytics Workspace.

### Steps:

1. In the search bar, type **"Microsoft Sentinel"**
2. Click **"Microsoft Sentinel"** from results
3. Click **"+ Create"**
4. Select your workspace: `SOC-Lab-Workspace`
5. Click **"Add"**
6. Wait for Sentinel to be enabled (2-3 minutes)

> ✅ **Success:** You'll be taken to the Sentinel Overview dashboard

---

## Step 5: Explore Sentinel Dashboard

Take a moment to familiarize yourself with the Sentinel interface:

### Left Navigation Menu:

| Section | Purpose |
|---------|---------|
| **Overview** | High-level security metrics |
| **Incidents** | Security alerts grouped for investigation |
| **Workbooks** | Dashboards and visualizations |
| **Hunting** | Proactive threat hunting queries |
| **Notebooks** | Jupyter notebooks for advanced analysis |
| **Entity behavior** | User and entity analytics (UEBA) |
| **Threat intelligence** | IOC management |
| **MITRE ATT&CK** | Attack framework coverage |
| **Content hub** | Pre-built solutions and connectors |
| **Repositories** | GitOps for Sentinel content |
| **Community** | Links to community resources |
| **Data connectors** | Connect log sources |
| **Analytics** | Detection rules |
| **Automation** | Playbooks and automation rules |
| **Settings** | Workspace configuration |

---

## Step 6: Configure Data Retention

Set how long logs are kept (affects costs).

### Steps:

1. In Sentinel, click **"Settings"** (bottom left)
2. Click **"Workspace settings"**
3. In Log Analytics, click **"Usage and estimated costs"** (left menu)
4. Click **"Data Retention"**
5. Set to **30 days** (free tier)
6. Click **"OK"**

---

## Step 7: Set Up Budget Alert (Important!)

Protect your $100 credit by setting up cost alerts.

### Steps:

1. In the search bar, type **"Cost Management"**
2. Click **"Cost Management + Billing"**
3. Click **"Cost Management"** in the left menu
4. Click **"Budgets"**
5. Click **"+ Add"**
6. Fill in:

| Field | Value |
|-------|-------|
| **Name** | `SOC-Lab-Budget` |
| **Reset period** | Monthly |
| **Amount** | `$20` |

7. Click **"Next"**
8. Add alert conditions:

| Alert | Threshold | Action |
|-------|-----------|--------|
| Alert 1 | 50% ($10) | Email notification |
| Alert 2 | 80% ($16) | Email notification |
| Alert 3 | 100% ($20) | Email notification |

9. Enter your email address
10. Click **"Create"**

> ⚠️ **Important:** This helps prevent unexpected charges!

---

## Verification Checklist

Before moving on, verify these items:

| Item | Status |
|------|--------|
| Resource Group `SOC-Lab-RG` created | ⬜ |
| Log Analytics Workspace `SOC-Lab-Workspace` created | ⬜ |
| Microsoft Sentinel enabled on workspace | ⬜ |
| Data retention set to 30 days | ⬜ |
| Budget alert configured | ⬜ |

---

## Cost Summary (This Phase)

| Resource | Cost |
|----------|------|
| Resource Group | FREE |
| Log Analytics Workspace | FREE (first 5GB/day) |
| Microsoft Sentinel | FREE (first 10GB/day for 31 days) |
| **Total** | **$0** |

---

## Troubleshooting

### "I don't see Microsoft Sentinel"
- Make sure you're searching for "Microsoft Sentinel" (it was renamed from Azure Sentinel)
- Check your subscription has the required permissions

### "Deployment failed"
- Check your subscription is active
- Try a different region
- Ensure resource names don't have special characters

### "I can't create a workspace"
- Verify you have Contributor role on the subscription
- Check if there's a policy blocking resource creation

---

## What's Next?

In the next phase, we'll deploy a Windows VM honeypot to attract attackers!

➡️ **Next:** [Phase 2: Deploy Honeypot VM](02-honeypot-deployment.md)

---

## Quick Reference

### Resources Created This Phase:

```
SOC-Lab-RG (Resource Group)
└── SOC-Lab-Workspace (Log Analytics)
    └── Microsoft Sentinel (SIEM)
```

### Useful Links:
- [Microsoft Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [Log Analytics Documentation](https://docs.microsoft.com/azure/azure-monitor/logs/)
- [Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/)

---

[← Back to Main README](../README.md) | [Next: Deploy Honeypot →](02-honeypot-deployment.md)
