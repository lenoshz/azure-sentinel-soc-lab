# ⚡ Phase 5: Automation Playbooks

This guide walks you through setting up automated incident response using Logic Apps.

**⏱️ Estimated Time:** 1 hour

---

## Overview

Playbooks are automated workflows that respond to security incidents. They use Azure Logic Apps to:

- 🛡️ Block malicious IPs automatically
- 📧 Send notifications to the SOC team
- 🔍 Enrich alerts with threat intelligence
- 📝 Create tickets in ITSM systems

### SOAR Benefits:

| Manual Response | Automated Response |
|-----------------|-------------------|
| 15-30 min per alert | Seconds |
| Human error possible | Consistent execution |
| Limited by staffing | 24/7 operation |
| Analyst fatigue | Focus on critical tasks |

---

## Prerequisites

Before creating playbooks:

1. ✅ Azure Sentinel workspace configured
2. ✅ Detection rules created (from Phase 4)
3. ✅ Owner or Contributor role on the resource group

---

## Step 1: Set Up Permissions

Playbooks need permissions to interact with Sentinel.

### Create Managed Identity:

1. Go to **Microsoft Sentinel**
2. Click **Settings** → **Workspace settings**
3. Click **"Identity"** (left menu)
4. Toggle **"System assigned"** to **On**
5. Click **"Save"**

### Assign Roles:

1. Go to your **Resource Group** (`SOC-Lab-RG`)
2. Click **"Access control (IAM)"**
3. Click **"+ Add"** → **"Add role assignment"**
4. Assign these roles to your managed identity:

| Role | Purpose |
|------|---------|
| Microsoft Sentinel Responder | Update incidents |
| Logic App Contributor | Run playbooks |

---

## Step 2: Create Notification Playbook

Let's start with a simple email notification playbook.

### Navigate to Logic Apps:

1. In Azure Portal, search for **"Logic Apps"**
2. Click **"+ Add"**
3. Fill in:

| Field | Value |
|-------|-------|
| **Subscription** | Your subscription |
| **Resource Group** | `SOC-Lab-RG` |
| **Logic App name** | `Notify-SOC-Team` |
| **Region** | Same as Sentinel workspace |
| **Plan type** | Consumption |

4. Click **"Review + create"** → **"Create"**

### Design the Workflow:

1. Click **"Go to resource"**
2. Click **"Logic app designer"**
3. Search for **"Microsoft Sentinel incident"**
4. Select **"When Microsoft Sentinel incident creation rule was triggered"**

### Add Connection:

1. Click **"Sign in"**
2. Select your account
3. Authorize the connection

### Add Email Action:

1. Click **"+ New step"**
2. Search for **"Office 365 Outlook"** (or Gmail)
3. Select **"Send an email (V2)"**
4. Sign in to authorize

### Configure Email:

| Field | Value |
|-------|-------|
| **To** | your-email@example.com |
| **Subject** | `🚨 Sentinel Alert: [Incident Title]` |
| **Body** | See template below |

**Email Body Template:**

```html
<h2>🚨 Security Incident Detected</h2>

<b>Incident:</b> @{triggerBody()?['object']?['properties']?['title']}<br>
<b>Severity:</b> @{triggerBody()?['object']?['properties']?['severity']}<br>
<b>Status:</b> @{triggerBody()?['object']?['properties']?['status']}<br>
<b>Created:</b> @{triggerBody()?['object']?['properties']?['createdTimeUtc']}<br>

<h3>Description</h3>
@{triggerBody()?['object']?['properties']?['description']}

<h3>Entities</h3>
@{triggerBody()?['object']?['properties']?['relatedEntities']}

<p>
<a href="@{triggerBody()?['object']?['properties']?['incidentUrl']}">
View in Sentinel
</a>
</p>
```

5. Click **"Save"**

### Connect to Sentinel:

1. Go back to **Microsoft Sentinel**
2. Click **"Automation"** (left menu)
3. Click **"+ Create"** → **"Automation rule"**
4. Configure:

| Field | Value |
|-------|-------|
| **Name** | `Auto-Notify-SOC-Medium-High` |
| **Trigger** | When incident is created |
| **Conditions** | Severity >= Medium |
| **Actions** | Run playbook → `Notify-SOC-Team` |

5. Click **"Apply"**

---

## Step 3: Create IP Blocking Playbook

This playbook automatically blocks malicious IPs in the NSG.

### Create the Logic App:

1. Create new Logic App: `Block-Malicious-IP`
2. Use trigger: **"When Microsoft Sentinel incident creation rule was triggered"**

### Add Steps:

#### Step 1: Get Incident Entities

1. Click **"+ New step"**
2. Search for **"Entities - Get IPs"**
3. Select **"Entities - Get IPs (Preview)"**
4. Configure:
   - **Entities List**: `@{triggerBody()?['object']?['properties']?['relatedEntities']}`

#### Step 2: For Each IP

1. Click **"+ New step"**
2. Search for **"Control"**
3. Select **"For each"**
4. **Select an output**: `@{body('Entities_-_Get_IPs')?['IPs']}`

#### Step 3: Add NSG Rule (Inside For Each)

1. Inside the For Each, click **"Add an action"**
2. Search for **"Azure Resource Manager"**
3. Select **"Create or update a resource"**

Configure:

| Field | Value |
|-------|-------|
| **Subscription** | Your subscription ID |
| **Resource Group** | `SOC-Lab-RG` |
| **Resource Provider** | Microsoft.Network |
| **Resource Type** | networkSecurityGroups/securityRules |
| **Resource Name** | `Honeypot-VM-nsg/Block-@{items('For_each')?['Address']}` |
| **API Version** | 2023-04-01 |

**Request Body:**

```json
{
  "properties": {
    "protocol": "*",
    "sourceAddressPrefix": "@{items('For_each')?['Address']}",
    "sourcePortRange": "*",
    "destinationAddressPrefix": "*",
    "destinationPortRange": "*",
    "access": "Deny",
    "priority": @{add(100, rand(1, 1000))},
    "direction": "Inbound"
  }
}
```

#### Step 4: Add Incident Comment

1. Click **"+ New step"** (after For Each)
2. Search for **"Microsoft Sentinel"**
3. Select **"Add comment to incident (V3)"**

Configure:

| Field | Value |
|-------|-------|
| **Incident ARM ID** | `@{triggerBody()?['object']?['id']}` |
| **Message** | `🛡️ Automated Response: Blocked IP addresses in NSG` |

5. Click **"Save"**

---

## Step 4: Create Threat Intel Enrichment Playbook

This playbook queries VirusTotal for IP reputation.

> 📝 **Note:** Requires free VirusTotal API key from https://www.virustotal.com

### Create the Logic App:

1. Create new Logic App: `Enrich-Threat-Intel`
2. Use trigger: **"When Microsoft Sentinel incident creation rule was triggered"**

### Add Steps:

#### Step 1: Get IPs

Same as before - use **"Entities - Get IPs"**

#### Step 2: For Each IP - Query VirusTotal

1. Inside For Each, click **"Add an action"**
2. Search for **"HTTP"**
3. Select **"HTTP"**

Configure:

| Field | Value |
|-------|-------|
| **Method** | GET |
| **URI** | `https://www.virustotal.com/api/v3/ip_addresses/@{items('For_each')?['Address']}` |
| **Headers** | `x-apikey`: `YOUR_VIRUSTOTAL_API_KEY` |

#### Step 3: Parse Response

1. Click **"+ New step"**
2. Search for **"Parse JSON"**
3. Configure with VirusTotal response schema

#### Step 4: Add Enriched Comment

```
🔍 Threat Intelligence Enrichment

IP: @{items('For_each')?['Address']}
Malicious Votes: @{body('Parse_JSON')?['data']?['attributes']?['last_analysis_stats']?['malicious']}
Harmless Votes: @{body('Parse_JSON')?['data']?['attributes']?['last_analysis_stats']?['harmless']}
Country: @{body('Parse_JSON')?['data']?['attributes']?['country']}
```

---

## Step 5: Connect Playbooks to Rules

### Using Automation Rules:

1. Go to **Microsoft Sentinel** → **Automation**
2. Click **"+ Create"** → **"Automation rule"**
3. Configure each playbook trigger:

| Rule Name | Trigger Condition | Playbook |
|-----------|------------------|----------|
| Auto-Notify-All | Severity >= Medium | Notify-SOC-Team |
| Auto-Block-Critical | Severity = High/Critical | Block-Malicious-IP |
| Auto-Enrich-All | Severity >= Low | Enrich-Threat-Intel |

### Or Attach Directly to Analytics Rule:

1. Go to **Analytics** → select a rule
2. Click **"Edit"**
3. Go to **"Automated response"** tab
4. Select your playbook
5. Save the rule

---

## Step 6: Test Your Playbooks

### Generate a Test Incident:

1. From an external IP, attempt 15+ failed RDP logins
2. Wait for the detection rule to trigger
3. Check **Incidents** page

### Verify Playbook Execution:

1. Go to your Logic App
2. Click **"Run history"**
3. Click on a run to see execution details
4. Green checkmarks = success

### Troubleshooting Failed Runs:

| Error | Solution |
|-------|----------|
| Unauthorized | Check connection permissions |
| Resource not found | Verify resource IDs |
| Timeout | Check API availability |
| Invalid JSON | Verify body formatting |

---

## Advanced Playbook: Full Response Chain

Combine multiple actions in one playbook:

```
Incident Triggered
       │
       ▼
  Get IP Entities
       │
       ▼
   For Each IP ──────────────────────────────────────┐
       │                                              │
       ├──▶ Check AbuseIPDB ──▶ High Score? ──Yes──▶ Block IP
       │                              │
       │                              No
       │                              │
       ├──▶ Check VirusTotal ──▶ Malicious? ──Yes──▶ Block IP
       │                              │
       │                              No
       │                              │
       └──▶ Add watchlist entry ◀────┘
       │
       ▼
  Update Incident ──▶ Add enrichment comments
       │
       ▼
  Send Notification ──▶ Email/Teams
```

---

## Cost Considerations

| Resource | Free Tier | Cost After |
|----------|-----------|------------|
| Logic Apps | 4,000 actions/month | ~$0.000125/action |
| VirusTotal API | 500 requests/day | Paid plans available |
| AbuseIPDB | 1,000 checks/day | Free tier usually sufficient |

> ✅ Our lab usage typically stays within free tiers!

---

## Security Best Practices

| Practice | Reason |
|----------|--------|
| Use managed identities | No credentials to manage |
| Limit playbook permissions | Least privilege |
| Log all playbook runs | Audit trail |
| Test in non-production first | Avoid blocking legitimate IPs |
| Review automation regularly | Tune for false positives |

---

## Verification Checklist

| Item | Status |
|------|--------|
| Notify-SOC-Team playbook created | ⬜ |
| Block-Malicious-IP playbook created | ⬜ |
| Enrich-Threat-Intel playbook created | ⬜ |
| Automation rules configured | ⬜ |
| Test incident triggered playbooks | ⬜ |
| Email notification received | ⬜ |

---

## What's Next?

Now let's build visual dashboards to monitor security!

➡️ **Next:** [Phase 6: Workbooks & Dashboards](06-workbooks-dashboards.md)

---

## Quick Reference

### Logic App Template Export:

To export your playbooks:
1. Go to Logic App
2. Click **"Logic app code view"**
3. Copy JSON
4. Save to `playbooks/logic-apps/` folder

### Playbook Naming Convention:

```
<Action>-<Target>-<Trigger>
Examples:
- Block-MaliciousIP-OnHighSeverity
- Notify-SOCTeam-OnMediumPlus
- Enrich-Incident-OnCreate
```

### Useful Dynamic Content:

| Expression | Value |
|------------|-------|
| `@{triggerBody()?['object']?['properties']?['title']}` | Incident title |
| `@{triggerBody()?['object']?['properties']?['severity']}` | Severity |
| `@{triggerBody()?['object']?['properties']?['incidentUrl']}` | Link to incident |
| `@{triggerBody()?['object']?['id']}` | Incident ARM ID |

---

[← Previous: Detection Rules](04-detection-rules.md) | [Next: Workbooks & Dashboards →](06-workbooks-dashboards.md)
