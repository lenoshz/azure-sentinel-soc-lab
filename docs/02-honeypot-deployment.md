# 🖥️ Phase 2: Deploy Honeypot VM

This guide walks you through deploying a Windows VM that will act as a honeypot to attract attackers.

**⏱️ Estimated Time:** 45 minutes

---

## What is a Honeypot?

A honeypot is a decoy system designed to:
- Attract attackers
- Log their activities
- Gather threat intelligence
- Test detection capabilities

Our honeypot will be a Windows VM with RDP exposed to the internet, attracting brute force attacks.

> ⚠️ **Warning:** This VM will be attacked! Never store sensitive data on it.

---

## Step 1: Create the Virtual Machine

### Navigate to Virtual Machines:

1. In Azure Portal, search for **"Virtual machines"**
2. Click **"Virtual machines"** from results
3. Click **"+ Create"** → **"Azure virtual machine"**

### Basics Tab:

| Field | Value |
|-------|-------|
| **Subscription** | Your subscription |
| **Resource group** | `SOC-Lab-RG` |
| **Virtual machine name** | `Honeypot-VM` |
| **Region** | `East US` (same as workspace) |
| **Availability options** | No infrastructure redundancy required |
| **Security type** | Standard |
| **Image** | Windows 10 Pro, version 22H2 - x64 Gen2 |
| **VM architecture** | x64 |
| **Size** | `Standard_B1s` (1 vCPU, 1 GB RAM) - cheapest! |
| **Username** | `psychonaut` (or your choice) |
| **Password** | Create a strong password (save it!) |
| **Confirm password** | Same as above |
| **Public inbound ports** | Allow selected ports |
| **Select inbound ports** | RDP (3389) |

> 💡 **Tip:** Use a unique username - attackers often try common names like "admin" or "administrator"

### Disks Tab:

| Field | Value |
|-------|-------|
| **OS disk type** | Standard SSD (cheaper) |
| **Delete with VM** | ✅ Checked |

### Networking Tab:

| Field | Value |
|-------|-------|
| **Virtual network** | (Create new) `SOC-Lab-VNet` |
| **Subnet** | (Create new) `default (10.0.0.0/24)` |
| **Public IP** | (Create new) `Honeypot-VM-ip` |
| **NIC network security group** | Basic |
| **Public inbound ports** | Allow selected ports |
| **Select inbound ports** | RDP (3389) |
| **Delete public IP and NIC when VM is deleted** | ✅ Checked |

### Management Tab:

| Field | Value |
|-------|-------|
| **Enable auto-shutdown** | ✅ Yes |
| **Shutdown time** | `7:00:00 PM` (your timezone) |
| **Time zone** | Your timezone |
| **Notification before shutdown** | Optional (add email) |

> 💰 **Cost Saving:** Auto-shutdown saves ~50% on VM costs!

### Monitoring Tab:

| Field | Value |
|-------|-------|
| **Boot diagnostics** | Disable |

### Review + Create:

1. Click **"Review + create"**
2. Review the summary
3. Click **"Create"**
4. Wait for deployment (3-5 minutes)

> ✅ **Success:** You should see "Your deployment is complete"

---

## Step 2: Note the Public IP Address

1. Click **"Go to resource"**
2. In the Overview page, find **"Public IP address"**
3. **Write this down** - you'll need it to connect and for testing

Example: `20.185.xxx.xxx`

---

## Step 3: Configure Network Security Group (NSG)

We need to ensure RDP is open to attract attackers.

### Steps:

1. In your VM overview, click **"Networking"** (left menu)
2. Click on the **Network Security Group** name (e.g., `Honeypot-VM-nsg`)
3. Click **"Inbound security rules"** (left menu)
4. You should see a rule allowing RDP (port 3389)

### Verify/Create RDP Rule:

If RDP rule doesn't exist, create it:

| Field | Value |
|-------|-------|
| **Source** | Any |
| **Source port ranges** | * |
| **Destination** | Any |
| **Service** | RDP |
| **Destination port ranges** | 3389 |
| **Protocol** | TCP |
| **Action** | Allow |
| **Priority** | 100 |
| **Name** | `Allow-RDP-All` |

5. Click **"Add"**

> ⚠️ **Note:** In production, you'd NEVER allow RDP from "Any". This is intentional for our honeypot!

---

## Step 4: Enable NSG Flow Logs (Optional but Recommended)

NSG Flow Logs capture network traffic metadata.

### Steps:

1. In the NSG, click **"NSG flow logs"** (left menu under Monitoring)
2. Click **"+ Create"**
3. Fill in:

| Field | Value |
|-------|-------|
| **Flow log name** | `Honeypot-NSG-FlowLog` |
| **Storage account** | Create new or use existing |
| **Retention (days)** | 7 |
| **Traffic Analytics** | Enable (optional, uses more data) |
| **Log Analytics Workspace** | `SOC-Lab-Workspace` |

4. Click **"Review + Create"** → **"Create"**

---

## Step 5: Connect to the VM

Let's verify the VM is working.

### Using Remote Desktop:

**On Windows:**
1. Press `Win + R`
2. Type `mstsc` and press Enter
3. Enter the Public IP address
4. Click **"Connect"**
5. Enter your username and password
6. Accept the certificate warning
7. You're now connected!

**On Mac:**
1. Download "Microsoft Remote Desktop" from App Store
2. Click **"+"** → **"Add PC"**
3. Enter the Public IP address
4. Double-click to connect
5. Enter credentials

**On Linux:**
```bash
rdesktop <PUBLIC_IP>
# or
xfreerdp /u:psychonaut /p:YourPassword /v:<PUBLIC_IP>
```

---

## Step 6: Configure Windows Security Logging

Inside the VM, we need to enable detailed security logging.

### Open Local Security Policy:

1. Press `Win + R`
2. Type `secpol.msc` and press Enter
3. Navigate to: **Local Policies** → **Audit Policy**

### Enable These Audit Policies:

| Policy | Setting |
|--------|---------|
| Audit account logon events | Success, Failure |
| Audit account management | Success, Failure |
| Audit logon events | Success, Failure |
| Audit object access | Failure |
| Audit policy change | Success, Failure |
| Audit privilege use | Failure |
| Audit process tracking | Success |
| Audit system events | Success, Failure |

For each policy:
1. Double-click the policy
2. Check both **"Success"** and **"Failure"**
3. Click **"OK"**

---

## Step 7: Disable Windows Firewall (Honeypot Only!)

To make the VM more attractive to attackers:

> ⚠️ **WARNING:** Only do this on your honeypot! NEVER on production systems!

1. Press `Win + R`
2. Type `wf.msc` and press Enter
3. Click **"Windows Defender Firewall Properties"**
4. For each profile (Domain, Private, Public):
   - Set **Firewall state** to **"Off"**
   - Click **"Apply"**
5. Click **"OK"**

---

## Step 8: Verify Event Logs are Working

1. Press `Win + R`
2. Type `eventvwr.msc` and press Enter
3. Navigate to: **Windows Logs** → **Security**
4. You should see events (Event ID 4624 for successful logins)

### Test Failed Login:
1. Disconnect from VM
2. Try to reconnect with a WRONG password
3. Reconnect with correct password
4. Check Event Viewer → Security
5. Look for Event ID **4625** (failed login)

---

## Step 9: Disconnect and Let It Attract Attacks

1. Log out of the VM (don't shut it down!)
2. The VM is now exposed to the internet
3. Attackers will start finding it within hours
4. We'll connect logs to Sentinel in the next phase

> 🎯 **What happens now:** Automated scanners constantly scan the internet for open RDP ports. Your VM will start receiving brute force attempts within 1-24 hours.

---

## Verification Checklist

| Item | Status |
|------|--------|
| VM `Honeypot-VM` created and running | ⬜ |
| Public IP address noted | ⬜ |
| RDP port 3389 open in NSG | ⬜ |
| Auto-shutdown configured | ⬜ |
| Can connect via RDP | ⬜ |
| Security audit policies enabled | ⬜ |
| Windows Firewall disabled | ⬜ |
| Event logs showing login events | ⬜ |

---

## Cost Summary (This Phase)

| Resource | Cost/Month | Notes |
|----------|------------|-------|
| Windows VM (B1s) | ~$8-10 | With auto-shutdown: ~$4-5 |
| Public IP | ~$3 | Static IP |
| Storage (30GB) | ~$1-2 | Standard SSD |
| **Total** | **~$8-15/month** | Well within $100 credit |

---

## Troubleshooting

### "Can't connect via RDP"
- Verify VM is running (not stopped/deallocated)
- Check NSG has RDP rule allowing traffic
- Confirm you're using the correct public IP
- Try restarting the VM

### "VM is too slow"
- B1s is the smallest size - expect some lag
- This is fine for a honeypot
- Don't run heavy applications

### "No security events appearing"
- Wait a few minutes after enabling audit policies
- Try a failed login to generate events
- Verify audit policies are set correctly

### "Auto-shutdown isn't working"
- Check the timezone is correct
- Verify auto-shutdown is enabled in VM settings
- Note: You need to manually start the VM each day

---

## What's Next?

Now we need to connect the VM logs to Azure Sentinel!

➡️ **Next:** [Phase 3: Data Connectors](03-data-connectors.md)

---

## Quick Reference

### Resources Created This Phase:

```
SOC-Lab-RG (Resource Group)
├── SOC-Lab-Workspace (Log Analytics)
│   └── Microsoft Sentinel (SIEM)
├── SOC-Lab-VNet (Virtual Network)
│   └── default (Subnet)
├── Honeypot-VM (Virtual Machine)
├── Honeypot-VM-ip (Public IP)
└── Honeypot-VM-nsg (Network Security Group)
```

### Important Information:
- **VM Public IP:** _____________ (fill in)
- **VM Username:** _____________ 
- **VM Password:** _____________ (keep secure!)

---

[← Previous: Azure Setup](01-azure-setup.md) | [Next: Data Connectors →](03-data-connectors.md)
